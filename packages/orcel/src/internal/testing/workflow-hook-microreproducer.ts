import { createHook } from "#compiled/@workflow/core/index.js";

/**
 * Benchmark-only Workflow SDK primitive, deliberately independent of Orcel
 * sessions, model calls, tools, and durable parent/child topology.
 */
export async function singleResumeWorkflow(input: { readonly token: string }): Promise<string> {
  "use workflow";
  using incoming = createHook<string>({ token: input.token });
  return await incoming;
}

/**
 * Two sequential public Workflow hook acknowledgments; this does NOT model
 * child creation, parent/child transfers, or inter-process clock domains.
 */
export async function doubleResumeWorkflow(input: {
  readonly firstToken: string;
  readonly secondToken: string;
}): Promise<readonly [string, string]> {
  "use workflow";
  using first = createHook<string>({ token: input.firstToken });
  const firstResult = await first;
  using second = createHook<string>({ token: input.secondToken });
  const secondResult = await second;
  return [firstResult, secondResult] as const;
}
