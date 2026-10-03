import type { BootstrapGenerateResult } from "#runtime/agent/bootstrap-model-utils.js";

export function createToolCallGenerateResult(input: {
  readonly input: unknown;
  readonly inputTokens: number;
  readonly modelId: string;
  readonly outputTokens: number;
  readonly toolCallId: string;
  readonly toolName: string;
}): BootstrapGenerateResult {
  return createToolCallsGenerateResult({
    calls: [{ input: input.input, toolCallId: input.toolCallId, toolName: input.toolName }],
    inputTokens: input.inputTokens,
    modelId: input.modelId,
    outputTokens: input.outputTokens,
  });
}

export function createToolCallsGenerateResult(input: {
  readonly calls: readonly {
    readonly input: unknown;
    readonly toolCallId: string;
    readonly toolName: string;
  }[];
  readonly inputTokens: number;
  readonly modelId: string;
  readonly outputTokens: number;
}): BootstrapGenerateResult {
  return {
    content: input.calls.map((call) => ({
      input: JSON.stringify(call.input),
      toolCallId: call.toolCallId,
      toolName: call.toolName,
      type: "tool-call",
    })),
    finishReason: { raw: undefined, unified: "tool-calls" },
    response: {
      id: "bootstrap-response",
      modelId: input.modelId,
      timestamp: new Date("2026-03-16T00:00:00.000Z"),
    },
    usage: {
      inputTokens: {
        cacheRead: 0,
        cacheWrite: 0,
        noCache: input.inputTokens,
        total: input.inputTokens,
      },
      outputTokens: {
        reasoning: 0,
        text: input.outputTokens,
        total: input.outputTokens,
      },
    },
    warnings: [],
  } as BootstrapGenerateResult;
}
