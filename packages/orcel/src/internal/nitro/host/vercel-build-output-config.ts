import { ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER_ENV } from "#internal/application/build-output-environment.js";
import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { ORCEL_FRAMEWORK_SLUG } from "#internal/package-name.js";
import { createOrcelWorkflowQueueTrigger } from "#internal/workflow/queue-namespace.js";
import { ORCEL_WORKFLOW_FLOW_ROUTE_PATH } from "#internal/workflow-bundle/orcel-service-route-output.js";
import {
  ORCEL_PUBLIC_ROUTE_PREFIX_ENV,
  normalizePublicRoutePrefix,
} from "#shared/public-route-prefix.js";

export { ORCEL_WORKFLOW_FLOW_ROUTE_PATH };

/**
 * Builds orcel's Vercel preset options.
 *
 * The flow route's `functionRules` entry makes Nitro emit a dedicated
 * `flow.func` from the same build output, carrying the agent's queue trigger,
 * an extended execution window, and the environment the deployed workflow
 * runtime needs. Every other function setting (runtime, memory, streaming) is
 * inherited from the base server function config.
 */
export function createOrcelVercelOptions(input: {
  agentName: string;
  enabled: boolean;
  publicRoutePrefix?: string;
  workspaceMember?: boolean;
}) {
  if (!input.enabled) {
    return undefined;
  }

  const environment: Record<string, string> = {
    // Reject replay decisions made from an event log that missed a
    // concurrent wake.
    WORKFLOW_PRECONDITION_GUARD: "1",
  };

  // Bake the agent's public mount into the flow function so callback-URL
  // minting inside the deployed workflow runtime resolves a routable path
  // when a multi-agent host proxies the agent behind a prefix.
  const publicRoutePrefix = normalizePublicRoutePrefix(input.publicRoutePrefix);
  if (publicRoutePrefix !== undefined) {
    environment[ORCEL_PUBLIC_ROUTE_PREFIX_ENV] = publicRoutePrefix;
  }
  if (input.workspaceMember === true) {
    environment[ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER_ENV] = "1";
  }

  return {
    config: {
      version: 3 as const,
      framework: {
        slug: ORCEL_FRAMEWORK_SLUG,
        version: resolveInstalledPackageInfo().version,
      },
    },
    functionRules: {
      [ORCEL_WORKFLOW_FLOW_ROUTE_PATH]: {
        maxDuration: "max" as const,
        experimentalTriggers: [createOrcelWorkflowQueueTrigger(input.agentName)],
        environment,
      },
    },
  };
}
