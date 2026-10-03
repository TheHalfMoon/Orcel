// ---------------------------------------------------------------------------
// Eval definition
// ---------------------------------------------------------------------------

export { defineEval } from "#evals/define-eval.js";
export { defineEvalConfig } from "#evals/define-eval-config.js";
export { OrcelEvalTurnFailedError } from "#evals/session.js";
export { mockModel } from "#evals/mock-model.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type { RuntimeIdentity, RuntimeTraceContext } from "#protocol/message.js";
export type { InputRequest } from "#shared/input.js";
export type { CancelSessionResult } from "#client/types.js";

export type {
  OrcelEvalCountMatcher,
  OrcelEvalEventMatch,
  OrcelEvalInputRequestMatchOptions,
  OrcelEvalValueMatcher,
  OrcelEvalToolCallMatchOptions,
  OrcelEvalSkillLoadMatchOptions,
  OrcelEvalSubagentCallMatchOptions,
} from "#evals/match.js";

export type {
  Assertion,
  AssertionEvaluation,
  AssertionHandle,
  AssertionResult,
  AssertionSeverity,
  OrcelEvalActionStatus,
  OrcelEvalAgentSession,
  OrcelEvalAssertions,
  OrcelEvalContext,
  OrcelEvalDerivedFacts,
  OrcelEvalJudgeConfig,
  OrcelEvalRunSummary,
  OrcelEvalSession,
  OrcelEvalSessionResult,
  OrcelEvalScheduleDispatchResult,
  OrcelEvalSubagentCall,
  OrcelEval,
  OrcelEvalConfig,
  OrcelEvalConfigInput,
  OrcelEvalConfigContext,
  OrcelEvalDefinition,
  OrcelEvalInput,
  OrcelEvalLiveTurn,
  OrcelEvalResult,
  OrcelEvalTarget,
  OrcelEvalTargetCapabilities,
  OrcelEvalTargetHandle,
  OrcelEvalTaskResult,
  OrcelEvalTraceContext,
  OrcelEvalToolCall,
  OrcelEvalTurn,
  OrcelEvalStreamEvent,
  OrcelEvalWaitForEventOptions,
  OrcelEvalVerdict,
  JudgeBatch,
  JudgeInput,
  JudgeQuestion,
  JudgeContext,
  JudgeOpts,
} from "#evals/types.js";

export type {
  MockModelMessage,
  MockModelOptions,
  MockModelRequest,
  MockModelResponder,
  MockModelResponse,
  MockModelTool,
  MockModelToolCall,
  MockModelToolResult,
  MockModelUsage,
} from "#evals/mock-model.js";
