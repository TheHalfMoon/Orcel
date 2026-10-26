// SG-000108 slice 6: native page extraction (Markdown) from an engine DOM
// snapshot. Pure functions: no page script, no network, no dependency. The
// worker and host wiring (a typed frame, host-side bounds and labelling as
// untrusted page text) is a separate change.

import { chunkMarkdown, type MarkdownChunk } from "./chunk.js";
import { contentModel, type LayoutSnapshot } from "./model.js";
import { toMarkdown } from "./markdown.js";
import { filterRelevant, type RelevanceOptions } from "./relevance.js";

export { CONTENT_STYLES } from "./model.js";
export type { MarkdownChunk } from "./chunk.js";
export type { RelevanceOptions } from "./relevance.js";

export interface ExtractOptions {
  links?: boolean;
  images?: boolean;
  /// Upper bound on the Markdown produced (characters).
  maxChars?: number;
  /// Upper bound on one chunk (characters, soft for a single larger block).
  chunkChars?: number;
  /// CPU budget for the whole extraction (milliseconds).
  budgetMs?: number;
  /// WI-03: keep only the blocks relevant to a query (BM25) or drop
  /// boilerplate (pruning). Absent, or BM25 with an empty query, keeps
  /// everything.
  relevance?: RelevanceOptions;
}

export interface Extraction {
  url: string;
  markdown: string;
  chunks: MarkdownChunk[];
  /// Content was dropped by a bound or the budget.
  truncated: boolean;
  /// A relevance filter was asked for and kept none of the page's text
  /// (an empty result, not an empty page).
  nothingRelevant: boolean;
}

export const EXTRACT_DEFAULTS = {
  maxChars: 1_000_000,
  chunkChars: 50_000,
  budgetMs: 4_000
} as const;

/// Extract the main document's rendered content as Markdown, split into
/// structure-aware chunks. `snapshot` must be a DOMSnapshot captured with
/// `computedStyles: CONTENT_STYLES`.
export function extractMarkdown(snapshot: LayoutSnapshot, options: ExtractOptions = {}): Extraction {
  const deadline = Date.now() + (options.budgetMs ?? EXTRACT_DEFAULTS.budgetMs);
  const model = contentModel(snapshot, deadline);
  const relevant = options.relevance
    ? filterRelevant(model.root, options.relevance, deadline)
    : { root: model.root, nothingRelevant: false, timedOut: false };
  const { markdown, truncated } = toMarkdown(relevant.root, {
    baseUrl: model.url,
    links: options.links ?? false,
    images: options.images ?? false,
    maxChars: options.maxChars ?? EXTRACT_DEFAULTS.maxChars,
    deadline
  });
  return {
    url: model.url,
    markdown,
    chunks: chunkMarkdown(markdown, options.chunkChars ?? EXTRACT_DEFAULTS.chunkChars, 5),
    truncated: model.truncated || relevant.timedOut || truncated,
    nothingRelevant: relevant.nothingRelevant
  };
}
