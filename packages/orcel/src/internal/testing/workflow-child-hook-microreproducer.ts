import { createHook, getWorkflowMetadata } from "#compiled/@workflow/core/index.js";
import { resumeHook, start } from "#internal/workflow/runtime.js";

interface ChildHookInput {
  readonly firstToken: string;
  readonly secondToken: string;
}

/**
 * Local-only parent/child primitive. The parent owns both hooks throughout:
 * it does not exercise ownership transfer or any cross-deployment handoff.
 */
export async function parentChildHookWorkflow(input: ChildHookInput): Promise<{
  readonly parentRunId: string;
  readonly childRunId: string;
  readonly payloads: readonly [string, string];
}> {
  "use workflow";
  const parentRunId = getWorkflowMetadata().workflowRunId;
  using first = createHook<string>({ token: input.firstToken });
  using second = createHook<string>({ token: input.secondToken });

  const childRunId = await startHookChildStep(input);
  const firstValue = await first;
  const secondValue = await second;
  return { parentRunId, childRunId, payloads: [firstValue, secondValue] };
}

/** Both acknowledgments originate in a distinct child Workflow run. */
export async function hookChildWorkflow(input: ChildHookInput): Promise<readonly [string, string]> {
  "use workflow";
  await acknowledgeParentHookStep(input.firstToken, "alpha");
  await acknowledgeParentHookStep(input.secondToken, "beta");
  return ["alpha", "beta"];
}

async function startHookChildStep(input: ChildHookInput): Promise<string> {
  "use step";
  const child = await start(hookChildWorkflow, [input]);
  return child.runId;
}

async function acknowledgeParentHookStep(token: string, payload: string): Promise<void> {
  "use step";
  await resumeHook(token, payload);
}
