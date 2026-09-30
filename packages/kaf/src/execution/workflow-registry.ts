declare global {
  // The Workflow SDK's generated entrypoint resolves a run's function from this
  // map; kaf's transform creates it and registers every `"use workflow"` function.
  var __private_workflows: Map<string, unknown> | undefined;
}

export const WORKFLOW_REGISTRY_GLOBAL = "__private_workflows";

export function readRegisteredWorkflow(workflowId: string): unknown {
  return globalThis[WORKFLOW_REGISTRY_GLOBAL]?.get(workflowId);
}
