// ---------------------------------------------------------------------------
// Eval definition
// ---------------------------------------------------------------------------

export { defineEval } from "#evals/define-eval.js";
export { defineEvalConfig } from "#evals/define-eval-config.js";
export { KafEvalTurnFailedError } from "#evals/session.js";
export { mockModel } from "#evals/mock-model.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type { RuntimeIdentity, RuntimeTraceContext } from "#protocol/message.js";
export type { InputRequest } from "#shared/input.js";
export type { CancelSessionResult } from "#client/types.js";

export type {
  KafEvalCountMatcher,
  KafEvalEventMatch,
  KafEvalInputRequestMatchOptions,
  KafEvalValueMatcher,
  KafEvalToolCallMatchOptions,
  KafEvalSkillLoadMatchOptions,
  KafEvalSubagentCallMatchOptions,
} from "#evals/match.js";

export type {
  Assertion,
  AssertionEvaluation,
  AssertionHandle,
  AssertionResult,
  AssertionSeverity,
  KafEvalActionStatus,
  KafEvalAgentSession,
  KafEvalAssertions,
  KafEvalContext,
  KafEvalDerivedFacts,
  KafEvalJudgeConfig,
  KafEvalRunSummary,
  KafEvalSession,
  KafEvalSessionResult,
  KafEvalScheduleDispatchResult,
  KafEvalSubagentCall,
  KafEval,
  KafEvalConfig,
  KafEvalConfigInput,
  KafEvalConfigContext,
  KafEvalDefinition,
  KafEvalInput,
  KafEvalLiveTurn,
  KafEvalResult,
  KafEvalTarget,
  KafEvalTargetCapabilities,
  KafEvalTargetHandle,
  KafEvalTaskResult,
  KafEvalTraceContext,
  KafEvalToolCall,
  KafEvalTurn,
  KafEvalStreamEvent,
  KafEvalWaitForEventOptions,
  KafEvalVerdict,
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
