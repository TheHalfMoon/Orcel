import { defineTool } from "@orcel/orcel/tools";
import { never } from "@orcel/orcel/tools/approval";
import { bash } from "@orcel/orcel/tools/bash";

/**
 * Bash tool exposed to the model for sandbox preparation smoke
 * test. `approval: never()` keeps the smoke test single-turn
 * and avoids tripping the HITL machinery already exercised by
 * `tool-approval.ts` / `tool-denial.ts`.
 *
 * Wrapping the framework's `bash` definition in `defineTool({...})`
 * gives the inferred default a named return type so tsc does not
 * trip the TS2883 "inferred type cannot be named" portability
 * check.
 */
export default defineTool({
  ...bash,
  approval: never(),
});
