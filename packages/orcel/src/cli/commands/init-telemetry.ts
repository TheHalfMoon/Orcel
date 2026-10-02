import type { OrcelCliSetupFailureCode } from "#cli/telemetry/index.js";

type InitTargetFailureCode = Extract<
  OrcelCliSetupFailureCode,
  "target_conflict" | "target_filesystem" | "target_invalid" | "workspace_input"
>;

export class InitTargetError extends Error {
  readonly failureCode: InitTargetFailureCode;

  constructor(failureCode: InitTargetFailureCode, message: string) {
    super(message);
    this.failureCode = failureCode;
  }
}
