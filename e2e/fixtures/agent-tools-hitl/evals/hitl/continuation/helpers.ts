import type {
  KafEvalContext,
  KafEvalLiveTurn,
  KafEvalSession,
  KafEvalTurn,
  InputRequest,
} from "kaf/evals";
import { equals, satisfies } from "kaf/evals/expect";

export const scriptedSession = { headers: { "x-kaf-fixture-model": "continuation" } };

export function requestFrom(turn: KafEvalTurn, toolName: string): InputRequest {
  turn.expectOk();
  const matches = turn.inputRequests.filter((request) => request.action.toolName === toolName);
  if (matches.length !== 1)
    throw new Error(`Expected one ${toolName} request; found ${matches.length}.`);
  return matches[0]!;
}

export async function expectReply(
  t: KafEvalContext,
  live: KafEvalLiveTurn,
  expected: string | RegExp,
  owner?: string,
): Promise<KafEvalTurn> {
  t.log(`Accepted input in ${live.sessionId}; awaiting the reply and its turn completion.`);
  const turnId = owner ?? (await live.waitForEvent("message.received")).data.turnId;
  const turn = (await live.result()).expectOk();
  const replies = turn.events.filter(
    (event) =>
      event.type === "message.completed" &&
      event.data.turnId === turnId &&
      typeof event.data.message === "string" &&
      (typeof expected === "string"
        ? event.data.message === expected
        : expected.test(event.data.message)),
  );
  await t.require(
    replies.length,
    satisfies<number>(
      (count) => count === 1,
      `Exactly one reply matching ${String(expected)} in ${turnId}`,
    ),
  );
  const completions = turn.events.filter(
    (event) => event.type === "turn.completed" && event.data.turnId === turnId,
  );
  await t.require(
    completions.length,
    satisfies<number>((count) => count === 1, `Exactly one completion for ${turnId}`),
  );
  turn.eventOrder([
    { type: "message.completed", data: { turnId, message: expected }, count: 1 },
    { type: "turn.completed", data: { turnId }, count: 1 },
  ]);
  turn.notEvent("input.requested", { data: { turnId } });
  t.log(`Checking answer and completion for ${turnId}.`);
  return turn;
}

export async function expectResponseReply(
  t: KafEvalContext,
  live: KafEvalLiveTurn,
  expected: string | RegExp,
  requestId: string,
): Promise<KafEvalTurn> {
  t.log(`Accepted response for ${requestId}; awaiting resolution and its resumed turn.`);
  await live.waitForEvent("input.resolved", {
    data: { resolutions: (items) => items.some((item) => item.requestId === requestId) },
  });
  // Several responses in one delivery can resolve during the same resumed turn.
  const resumed = await live.waitForEvent("turn.started");
  const turn = await expectReply(t, live, expected, resumed.data.turnId);
  turn.eventOrder([
    {
      type: "input.resolved",
      data: {
        resolutions: (items) =>
          items.some(
            (item) =>
              item.requestId === requestId &&
              item.outcome !== "ignored" &&
              item.outcome !== "invalid",
          ),
      },
      count: 1,
    },
    {
      type: "message.completed",
      data: { turnId: resumed.data.turnId, message: expected },
      count: 1,
    },
    { type: "turn.completed", data: { turnId: resumed.data.turnId }, count: 1 },
  ]);
  turn.eventOrder([
    { type: "turn.started", data: { turnId: resumed.data.turnId }, count: 1 },
    {
      type: "message.completed",
      data: { turnId: resumed.data.turnId, message: expected },
      count: 1,
    },
  ]);
  return turn;
}

export async function expectToolResult(t: KafEvalContext, live: KafEvalLiveTurn, toolName: string) {
  t.log(`Accepted input in ${live.sessionId}; awaiting ${toolName}.`);
  const event = await live.waitForEvent("action.result", { data: { result: { toolName } } });
  t.log(`${toolName} returned before the reply: ${JSON.stringify(event.data)}`);
  return event;
}

export function expectChangeStillUnexecuted(session: KafEvalSession, toolName = "change-a") {
  session.notEvent("action.result", { data: { result: { toolName } } });
}

// A partial approval has no turn boundary to await. Await the real HTTP
// acceptance, then send the next message on that same session's ordered inbox.
export async function submitPartialApproval(
  t: KafEvalContext,
  session: KafEvalSession,
  request: InputRequest,
) {
  const response = await t.target.fetch(
    `/kaf/v1/session/${encodeURIComponent(session.sessionId)}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: t.signal,
      body: JSON.stringify({
        inputResponses: [{ requestId: request.requestId, optionId: "approve" }],
      }),
    },
  );
  await t.require(response.status, equals(202));
  const accepted = await response.json();
  t.log(`Partial approval accepted: ${JSON.stringify(accepted)}`);
}

export async function approveSavedChange(
  t: KafEvalContext,
  session: KafEvalSession,
  request: InputRequest,
) {
  const live = await session.startRespond([{ requestId: request.requestId, optionId: "approve" }]);
  const approved = await expectResponseReply(t, live, /\S/, request.requestId);
  approved.calledTool(request.action.toolName, {
    status: "completed",
    output: { executions: 1 },
    count: 1,
  });
  session.event("action.result", {
    data: { result: { toolName: request.action.toolName } },
    count: 1,
  });
}
