/** Environment flag set for processes that belong to an `kaf dev` session. */
export const KAF_DEV_ENV_FLAG = "KAF_DEV";

type InstrumentationEnvironment = "development" | "preview" | "production";

/** Reports whether this process belongs to an `kaf dev` session. */
export function isKafDevEnvironment(): boolean {
  return process.env[KAF_DEV_ENV_FLAG] === "1";
}

/** Resolves the deployment environment used by setup hooks and trace policies. */
export function resolveInstrumentationEnvironment(): InstrumentationEnvironment {
  if (isKafDevEnvironment() || process.env.VERCEL_ENV === "development") return "development";
  return process.env.VERCEL_ENV === "preview" ? "preview" : "production";
}

/** Environment flag set for a server `kaf eval` started to run against. */
export const KAF_EVALUATION_ENV_FLAG = "KAF_EVALUATION";

/** Stable identifier for the local eval run this server was started to serve. */
export const KAF_EVALUATION_RUN_ID_ENV = "KAF_EVALUATION_RUN_ID";

/**
 * Reports whether this process exists to serve an eval run.
 *
 * False for a server that `kaf eval --url` merely points at: that process was
 * started to serve ordinary traffic and cannot know an eval is among it.
 */
function isKafEvaluationEnvironment(): boolean {
  return process.env[KAF_EVALUATION_ENV_FLAG] === "1";
}

export function resolveKafEvaluationRunId(): string | undefined {
  if (!isKafEvaluationEnvironment()) return undefined;
  const runId = process.env[KAF_EVALUATION_RUN_ID_ENV];
  return runId === undefined || runId.length === 0 ? undefined : runId;
}
