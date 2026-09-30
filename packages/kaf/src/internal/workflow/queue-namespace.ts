export const WORKFLOW_QUEUE_NAMESPACE_ENV = "WORKFLOW_QUEUE_NAMESPACE";

/** Derives a stable Workflow queue namespace from an kaf agent's unique name. */
export function deriveKafWorkflowQueueNamespace(agentName: string): string {
  const encodedAgentName = Array.from(new TextEncoder().encode(agentName), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return `kaf${encodedAgentName}`;
}

/** Derives the queue prefix consumed by an kaf agent's workflow handler. */
export function deriveKafWorkflowQueuePrefix(agentName: string): string {
  return `__${deriveKafWorkflowQueueNamespace(agentName)}_wkf_workflow_`;
}

/** Derives the queue topic registered for an kaf agent's workflow handler. */
export function deriveKafWorkflowQueueTopic(agentName: string): string {
  return `${deriveKafWorkflowQueuePrefix(agentName)}*`;
}

/** Builds the Vercel queue trigger that invokes an kaf agent's flow function. */
export function createKafWorkflowQueueTrigger(agentName: string) {
  return {
    type: "queue/v2beta" as const,
    topic: deriveKafWorkflowQueueTopic(agentName),
    consumer: "default",
    retryAfterSeconds: 5,
    initialDelaySeconds: 0,
  };
}

/** Installs the agent-scoped namespace used by Workflow runtime operations. */
export function installKafWorkflowQueueNamespace(agentName: string): string {
  const namespace = deriveKafWorkflowQueueNamespace(agentName);
  process.env[WORKFLOW_QUEUE_NAMESPACE_ENV] = namespace;
  return namespace;
}
