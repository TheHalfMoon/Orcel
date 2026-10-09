import { createHook } from "#compiled/@workflow/core/index.js";

/**
 * Local-only research: a victim owns a stable token until a second run
 * requests the SDK's experimental forced claim.
 */
export async function forceClaimResearchVictim(input: { readonly token: string }): Promise<string> {
  "use workflow";
  using hook = createHook<string>({ token: input.token });
  return await hook;
}

/** This does not implement or exercise an Orcel successor session handoff. */
export async function forceClaimResearchSuccessor(input: {
  readonly token: string;
}): Promise<string> {
  "use workflow";
  using hook = createHook<string>({ token: input.token, experimental_force: true });
  return await hook;
}
