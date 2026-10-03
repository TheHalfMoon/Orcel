export const WORKFLOW_QUEUE_NAMESPACE_ENV = "WORKFLOW_QUEUE_NAMESPACE";

/** Derives a stable Workflow queue namespace from an orcel agent's unique name. */
export function deriveOrcelWorkflowQueueNamespace(agentName: string): string {
  const encodedAgentName = Array.from(new TextEncoder().encode(agentName), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return `orcel${encodedAgentName}`;
}

/** Derives the queue prefix consumed by an orcel agent's workflow handler. */
export function deriveOrcelWorkflowQueuePrefix(agentName: string): string {
  return `__${deriveOrcelWorkflowQueueNamespace(agentName)}_wkf_workflow_`;
}

/** Derives the queue topic registered for an orcel agent's workflow handler. */
export function deriveOrcelWorkflowQueueTopic(agentName: string): string {
  return `${deriveOrcelWorkflowQueuePrefix(agentName)}*`;
}

/** Builds the Vercel queue trigger that invokes an orcel agent's flow function. */
export function createOrcelWorkflowQueueTrigger(agentName: string) {
  return {
    type: "queue/v2beta" as const,
    topic: deriveOrcelWorkflowQueueTopic(agentName),
    consumer: "default",
    retryAfterSeconds: 5,
    initialDelaySeconds: 0,
  };
}

/** Installs the agent-scoped namespace used by Workflow runtime operations. */
export function installOrcelWorkflowQueueNamespace(agentName: string): string {
  const namespace = deriveOrcelWorkflowQueueNamespace(agentName);
  process.env[WORKFLOW_QUEUE_NAMESPACE_ENV] = namespace;
  return namespace;
}
