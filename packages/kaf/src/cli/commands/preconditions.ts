import type { KafProjectContext } from "#internal/project-context.js";
import { findKafProjectContext } from "#internal/project-context.js";
import { isKafProject } from "#setup/scaffold/index.js";

/**
 * Refusal shown by agent-scoped commands (`kaf link`, `kaf deploy`,
 * `kaf channels …`) when the working directory holds no kaf agent.
 */
export const NOT_AN_AGENT_MESSAGE =
  "No kaf agent in this directory. Run `kaf init <name>`, then run this command from inside the new project.";

interface ProjectCommandLogger {
  error(message: string): void;
}

/** Validate that a Vercel project command targets a workspace root or an kaf app. */
export async function validateWorkspaceProjectCommand(input: {
  readonly appRoot: string;
  readonly isKafProject?: typeof isKafProject;
  readonly logger: ProjectCommandLogger;
  readonly workspaceMemberMessage: (
    workspace: Extract<KafProjectContext, { kind: "workspace" }>["workspace"],
  ) => string;
}): Promise<boolean> {
  const projectContext = await findKafProjectContext(input.appRoot);
  if (projectContext?.kind === "workspace-member") {
    input.logger.error(input.workspaceMemberMessage(projectContext.workspace));
    process.exitCode = 1;
    return false;
  }
  if (
    projectContext === undefined ||
    (projectContext.kind === "standalone" &&
      !(await (input.isKafProject ?? isKafProject)(input.appRoot)))
  ) {
    input.logger.error(NOT_AN_AGENT_MESSAGE);
    process.exitCode = 1;
    return false;
  }
  return true;
}

/** True when stdin and stdout are both TTYs — the default interactivity gate. */
export function hasInteractiveTerminal(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}
