// W2-03: resolve an outline element id (as a model or a cached plan would
// name it) to the element's XPath, role and accessible name, with no model.
//
// Adapted from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/services/actService.ts` (blob
// 17187189c111f8a668da90099da16bff0efeaa77: `normalizeActInferenceElement`,
// the element-id format check and the id-to-XPath lookup through the
// snapshot's XPath map with `trimTrailingTextNode`) and
// `packages/extension/services/observeService.ts` (blob
// 9d042ffa191a2af222d8ed4b0094c457c8db8086: the same lookup for observed
// elements). MIT License, Copyright (c) 2024 Browserbase Inc.; notice in
// docs/orcel/notices/stagehand-MIT.txt; provenance in
// docs/orcel/stagehand_provenance.json.
//
// Modifications for Orcel: this only resolves; it never acts. Stagehand's
// `takeDeterministicAction` runs a Playwright-style method on an XPath
// selector; in Orcel every action stays one of the existing approved worker
// actions (`activate`, `form_action`, `upload`) on an element the host
// approved by snapshot ref or by exact role and name (BR-01), so an outline
// target is only ever an input to the host's approval, never a second way to
// act. Drag-and-drop arguments, variable substitution, self-healing and the
// LLM calls are not ported.

import type { OutlineNode } from "./capture.js";
import { trimTrailingTextNode } from "./xpath.js";

export interface OutlineTarget {
  id: string;
  xpath: string;
  role: string;
  name: string;
}

/// Stagehand's element-id shape (`<frame ordinal>-<backend node id>`); the
/// outline only issues frame ordinal 0.
const ELEMENT_ID = /^\d+-\d+$/;

/// The outline node with this id, or null when the id is malformed, absent,
/// or names a node without an XPath.
export function resolveOutlineTarget(nodes: OutlineNode[], elementId: string): OutlineTarget | null {
  if (!ELEMENT_ID.test(elementId)) return null;
  const stack = [...nodes];
  while (stack.length) {
    const node = stack.pop()!;
    if (node.id === elementId) {
      const xpath = trimTrailingTextNode(node.xpath);
      if (!xpath) return null;
      return { id: node.id, xpath, role: node.role, name: node.name };
    }
    stack.push(...node.children);
  }
  return null;
}
