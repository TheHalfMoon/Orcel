import type { BootstrapGenerateResult } from "#runtime/agent/bootstrap-model-utils.js";
import type { AvailableBootstrapTool } from "#runtime/agent/mock-model-fixtures.js";
import { createToolCallGenerateResult } from "#runtime/agent/mock-model-result-builder.js";
import { isTaskReceiptText } from "#execution/tasks/render.js";
import { TASK_WAIT_TOOL_NAME } from "#protocol/task-tools.js";

export function createMockTaskReceiptWaitResult(input: {
  readonly isError: boolean;
  readonly output: unknown;
  readonly tools: readonly AvailableBootstrapTool[];
  readonly inputTokens: number;
  readonly modelId: string;
}): BootstrapGenerateResult | null {
  if (input.isError || !isTaskReceipt(input.output)) return null;
  if (!input.tools.some((tool) => tool.name === TASK_WAIT_TOOL_NAME)) return null;

  return createToolCallGenerateResult({
    input: {},
    inputTokens: input.inputTokens,
    modelId: input.modelId,
    outputTokens: 1,
    toolCallId: "call_task_wait",
    toolName: TASK_WAIT_TOOL_NAME,
  });
}

function isTaskReceipt(output: unknown): boolean {
  return typeof output === "string" && isTaskReceiptText(output);
}
