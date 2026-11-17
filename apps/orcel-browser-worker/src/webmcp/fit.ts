// SG-000108 slice 4: fit discovered tools into one reply frame in linear
// time. Each tool is encoded once and the longest prefix whose encoded size
// (plus the frame envelope) fits is kept; the rest are dropped and reported
// as truncated.

import { MAX_FRAME_BYTES } from "../protocol.js";
import type { DeclaredTool } from "./declarative.js";

/// Upper bound on the time between receiving `discover` and replying: the
/// capture deadline plus the discovery budget stay well inside the host's
/// 10 s observation deadline.
export const DISCOVERY_TOTAL_MS = 6_000;
/// Upper bound on the engine's DOM snapshot.
export const CAPTURE_TIMEOUT_MS = 3_000;

export interface Fitted {
  url: string;
  truncated: boolean;
  tools: DeclaredTool[];
}

export function fitTools(discId: number, url: string, truncated: boolean, tools: readonly DeclaredTool[], max = MAX_FRAME_BYTES): Fitted {
  // The envelope is measured with `truncated: false`, the longer spelling,
  // and the largest tab id (SG-000135 OB-03), so the bound holds whichever
  // values are sent.
  let used = Buffer.byteLength(JSON.stringify({ frame: "discovered", disc_id: discId, tab: 1_000_000, url, truncated: false, tools: [] }), "utf8");
  const kept: DeclaredTool[] = [];
  let cut = truncated;
  for (const tool of tools) {
    const size = Buffer.byteLength(JSON.stringify(tool), "utf8") + (kept.length > 0 ? 1 : 0);
    if (used + size > max) {
      cut = true;
      break;
    }
    used += size;
    kept.push(tool);
  }
  return { url, truncated: cut, tools: kept };
}
