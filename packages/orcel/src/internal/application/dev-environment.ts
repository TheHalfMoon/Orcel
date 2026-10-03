/** Environment flag set for processes that belong to an `orcel dev` session. */
export const ORCEL_DEV_ENV_FLAG = "ORCEL_DEV";

type InstrumentationEnvironment = "development" | "preview" | "production";

/** Reports whether this process belongs to an `orcel dev` session. */
export function isOrcelDevEnvironment(): boolean {
  return process.env[ORCEL_DEV_ENV_FLAG] === "1";
}

/** Resolves the deployment environment used by setup hooks and trace policies. */
export function resolveInstrumentationEnvironment(): InstrumentationEnvironment {
  if (isOrcelDevEnvironment() || process.env.VERCEL_ENV === "development") return "development";
  return process.env.VERCEL_ENV === "preview" ? "preview" : "production";
}

/** Environment flag set for a server `orcel eval` started to run against. */
export const ORCEL_EVALUATION_ENV_FLAG = "ORCEL_EVALUATION";

/** Stable identifier for the local eval run this server was started to serve. */
export const ORCEL_EVALUATION_RUN_ID_ENV = "ORCEL_EVALUATION_RUN_ID";

/**
 * Reports whether this process exists to serve an eval run.
 *
 * False for a server that `orcel eval --url` merely points at: that process was
 * started to serve ordinary traffic and cannot know an eval is among it.
 */
function isOrcelEvaluationEnvironment(): boolean {
  return process.env[ORCEL_EVALUATION_ENV_FLAG] === "1";
}

export function resolveOrcelEvaluationRunId(): string | undefined {
  if (!isOrcelEvaluationEnvironment()) return undefined;
  const runId = process.env[ORCEL_EVALUATION_RUN_ID_ENV];
  return runId === undefined || runId.length === 0 ? undefined : runId;
}
