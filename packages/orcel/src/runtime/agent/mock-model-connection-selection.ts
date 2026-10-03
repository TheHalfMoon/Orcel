import type { BootstrapGenerateResult } from "#runtime/agent/bootstrap-model-utils.js";
import {
  type AvailableBootstrapTool,
  createMockAuthoredToolInput,
  resolveWeatherCity,
} from "#runtime/agent/mock-model-fixtures.js";
import { createToolCallGenerateResult } from "#runtime/agent/mock-model-result-builder.js";

const CONNECTION_SEARCH_TOOL_NAME = "connection_search";
const EXPLICIT_CONNECTION_TOOL = /\bconnection__([a-z0-9_-]+)__([a-z0-9_-]+)\b/iu;
const CONNECTION_TOOL_PHRASE =
  /(?:`([^`]+)`|([a-z0-9_-]+))\s+connection(?:'s)?\s+(?:`([^`]+)`|([a-z0-9_-]+))\s+tool/iu;

interface MockConnectionRequest {
  readonly connection: string;
  readonly tool: string;
}

export function createMockConnectionSearchResult(input: {
  readonly tools: readonly AvailableBootstrapTool[];
  readonly message: string;
  readonly inputTokens: number;
  readonly modelId: string;
}): BootstrapGenerateResult | null {
  if (!input.tools.some((tool) => tool.name === CONNECTION_SEARCH_TOOL_NAME)) return null;
  const requested = parseRequestedConnectionTool(input.message);
  if (requested === null) return null;
  return createToolCallGenerateResult({
    input: { connection: requested.connection, keywords: requested.tool },
    inputTokens: input.inputTokens,
    modelId: input.modelId,
    outputTokens: 1,
    toolCallId: "call_connection_search",
    toolName: CONNECTION_SEARCH_TOOL_NAME,
  });
}

export function createMockConnectionToolAfterSearchResult(input: {
  readonly previousToolName: string;
  readonly tools: readonly AvailableBootstrapTool[];
  readonly message: string;
  readonly inputTokens: number;
  readonly modelId: string;
}): BootstrapGenerateResult | null {
  if (input.previousToolName !== CONNECTION_SEARCH_TOOL_NAME) return null;
  const requested = parseRequestedConnectionTool(input.message);
  if (requested === null) return null;
  const qualifiedName = `${requested.connection}__${requested.tool}`;
  const tool = input.tools.find((candidate) => candidate.name === qualifiedName);
  if (tool === undefined) return null;
  const toolInput = createMockAuthoredToolInput(
    tool,
    input.message,
    resolveWeatherCity(input.message),
  );
  return createToolCallGenerateResult({
    input: toolInput,
    inputTokens: input.inputTokens,
    modelId: input.modelId,
    outputTokens: 1,
    toolCallId: `call_${qualifiedName.replace(/[^a-z0-9]+/giu, "_")}`,
    toolName: qualifiedName,
  });
}

function parseRequestedConnectionTool(message: string): MockConnectionRequest | null {
  const explicit = EXPLICIT_CONNECTION_TOOL.exec(message);
  if (explicit?.[1] !== undefined && explicit[2] !== undefined) {
    return { connection: explicit[1], tool: explicit[2] };
  }
  const phrase = CONNECTION_TOOL_PHRASE.exec(message);
  const connection = phrase?.[1] ?? phrase?.[2];
  const tool = phrase?.[3] ?? phrase?.[4];
  return connection === undefined || tool === undefined ? null : { connection, tool };
}
