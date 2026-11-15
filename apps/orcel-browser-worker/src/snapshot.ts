// SG-000108 slice 3b: bounded accessibility snapshots for the host's
// SG-000076 observation policy.
//
// The source is Playwright's `ariaSnapshotJSON({ mode: "ai" })`, which covers
// shadow DOM and iframes and gives each element a ref. Measured: it reports
// a password field's value in clear text under role `textbox`, so role-based
// redaction alone would leak it. The worker therefore never forwards any
// field value: a node carries only its ref, role, accessible name, and (for
// links) the bounded link URL. The host issues node identities, applies
// SG-000076 redaction, digests and ceilings, and keeps raw names to itself,
// except (SG-000122 slice A5) the names of main-frame form controls the
// worker marks `named`: those it bounds, marks untrusted and passes on.

export const MAX_SNAPSHOT_NODES = 512;
export const MAX_SNAPSHOT_DEPTH = 16;
export const MAX_NAME_BYTES = 1024;
export const MAX_LINK_URL_BYTES = 2048;
/// Leaves room under the 64 KiB frame bound for the frame envelope.
export const MAX_SNAPSHOT_JSON_BYTES = 56 * 1024;

/// SG-000122: what a main-frame form control is, for the host's checks
/// before any form action (see `classifyControls`).
export type FormControl = "line" | "select" | "toggle";

export interface SnapshotNode {
  ref: string;
  role: string;
  name: string;
  url?: string;
  control?: FormControl;
  /// SG-000122 slice A5: this form control's name carries no embedded or
  /// referenced control's contribution (`nameControls`).
  named?: boolean;
  children: SnapshotNode[];
}

export interface BoundedSnapshot {
  nodes: SnapshotNode[];
  truncated: boolean;
}

const REF = /^(?:f\d+)?e\d+$/;
const ROLE = /^[a-z][a-z-]{0,39}$/;

function cut(text: string, maxBytes: number): string {
  const clean = text.replace(/[\u0000-\u001f\u007f]/g, " ");
  if (Buffer.byteLength(clean, "utf8") <= maxBytes) return clean;
  let out = "";
  for (const ch of clean) {
    if (Buffer.byteLength(out + ch, "utf8") > maxBytes) break;
    out += ch;
  }
  return out;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/// Convert an aria snapshot into the bounded, value-free form. Text-only
/// children (bare strings) are dropped: their content is already part of
/// the parent's accessible name or is page text the host does not need.
export function boundSnapshot(raw: unknown): BoundedSnapshot {
  let count = 0;
  let bytes = 0;
  let truncated = false;
  const visit = (value: unknown, depth: number): SnapshotNode | null => {
    if (!isObject(value)) return null;
    if (depth > MAX_SNAPSHOT_DEPTH || count >= MAX_SNAPSHOT_NODES) {
      truncated = true;
      return null;
    }
    const ref = typeof value.ref === "string" && REF.test(value.ref) ? value.ref : null;
    const role = typeof value.role === "string" && ROLE.test(value.role) ? value.role : null;
    if (ref === null || role === null) return null;
    const node: SnapshotNode = {
      ref,
      role,
      name: typeof value.name === "string" ? cut(value.name, MAX_NAME_BYTES) : "",
      children: []
    };
    if (role === "link" && typeof value.url === "string") node.url = cut(value.url, MAX_LINK_URL_BYTES);
    const size = Buffer.byteLength(JSON.stringify({ ...node, children: [] }), "utf8");
    if (bytes + size > MAX_SNAPSHOT_JSON_BYTES) {
      truncated = true;
      return null;
    }
    bytes += size;
    count += 1;
    if (Array.isArray(value.children)) {
      for (const child of value.children) {
        if (count >= MAX_SNAPSHOT_NODES || bytes >= MAX_SNAPSHOT_JSON_BYTES) {
          truncated = true;
          break;
        }
        const visited = visit(child, depth + 1);
        if (visited) node.children.push(visited);
      }
    }
    return node;
  };
  const roots = Array.isArray(raw) ? raw : [raw];
  const nodes: SnapshotNode[] = [];
  for (const root of roots) {
    const visited = visit(root, 0);
    if (visited) nodes.push(visited);
    if (truncated) break;
  }
  return { nodes, truncated };
}
