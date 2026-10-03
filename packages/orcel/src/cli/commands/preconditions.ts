import type { OrcelProjectContext } from "#internal/project-context.js";
import { findOrcelProjectContext } from "#internal/project-context.js";
import { isOrcelProject } from "#setup/scaffold/index.js";

/**
 * Refusal shown by agent-scoped commands (`orcel link`, `orcel deploy`,
 * `orcel channels …`) when the working directory holds no orcel agent.
 */
export const NOT_AN_AGENT_MESSAGE =
  "No orcel agent in this directory. Run `orcel init <name>`, then run this command from inside the new project.";

interface ProjectCommandLogger {
  error(message: string): void;
}

/** Validate that a Vercel project command targets a workspace root or an orcel app. */
export async function validateWorkspaceProjectCommand(input: {
  readonly appRoot: string;
  readonly isOrcelProject?: typeof isOrcelProject;
  readonly logger: ProjectCommandLogger;
  readonly workspaceMemberMessage: (
    workspace: Extract<OrcelProjectContext, { kind: "workspace" }>["workspace"],
  ) => string;
}): Promise<boolean> {
  const projectContext = await findOrcelProjectContext(input.appRoot);
  if (projectContext?.kind === "workspace-member") {
    input.logger.error(input.workspaceMemberMessage(projectContext.workspace));
    process.exitCode = 1;
    return false;
  }
  if (
    projectContext === undefined ||
    (projectContext.kind === "standalone" &&
      !(await (input.isOrcelProject ?? isOrcelProject)(input.appRoot)))
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
