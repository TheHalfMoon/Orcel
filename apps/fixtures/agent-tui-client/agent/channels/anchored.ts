import { defineChannel, POST } from "orcel/channels";

interface AnchorRequestBody {
  readonly marker?: string;
  readonly message?: string;
  readonly threadId?: string;
}

interface AnchorState {
  anchorToken: string | null;
  completedMessages: string[];
  completedTurns: number;
  turnIds: string[];
}

function initialState(anchorToken: string | null = null): AnchorState {
  return {
    anchorToken,
    completedMessages: [],
    completedTurns: 0,
    turnIds: [],
  };
}

function authFor(phase: "reply" | "start", marker: string) {
  return {
    attributes: { marker, phase },
    authenticator: "anchored-smoke",
    principalId: phase === "start" ? "anchor-origin" : "anchor-replier",
    principalType: "user",
  };
}

function readBody(body: unknown): Required<AnchorRequestBody> {
  const input = body && typeof body === "object" ? (body as AnchorRequestBody) : {};
  const threadId = input.threadId?.trim() || crypto.randomUUID();
  const marker = input.marker?.trim() || `anchor-marker-${threadId}`;
  const message = input.message?.trim() || "Reply with the single word: anchored.";
  return { marker, message, threadId };
}

export default defineChannel({
  state: initialState(),
  context(state) {
    return { state };
  },
  metadata(state) {
    return {
      anchorToken: state.anchorToken ?? "",
      turnCount: state.completedTurns,
    };
  },
  routes: [
    POST<AnchorState>("/anchor/start", async (request, { from, waitUntil }) => {
      const body = readBody(await request.json().catch(() => ({})));
      const anchorToken = `thread:${body.threadId}`;
      const initialContinuationToken = `pending:${body.threadId}`;
      waitUntil(
        from(initialContinuationToken).send(body.message, {
          auth: authFor("start", body.marker),
          state: initialState(anchorToken),
        }),
      );

      return Response.json({ ok: true, anchorToken, initialContinuationToken });
    }),

    POST<AnchorState>("/anchor/session", async (request, { resolveSession }) => {
      const body = readBody(await request.json().catch(() => ({})));
      const continuationToken = `pending:${body.threadId}`;
      const session = await resolveSession(continuationToken);
      return Response.json(
        { ok: session !== undefined, sessionId: session?.id ?? null },
        { status: session === undefined ? 202 : 200 },
      );
    }),

    POST<AnchorState>("/anchor/reply", async (request, { attachSession, waitUntil }) => {
      const rawBody = await request.json().catch(() => ({}));
      const body = readBody(rawBody);
      const anchorToken = `thread:${body.threadId}`;
      const sessionId =
        rawBody &&
        typeof rawBody === "object" &&
        "sessionId" in rawBody &&
        typeof rawBody.sessionId === "string"
          ? rawBody.sessionId.trim()
          : "";
      if (sessionId.length === 0) {
        return Response.json({ error: "sessionId is required", ok: false }, { status: 400 });
      }
      const session = attachSession(sessionId);
      waitUntil(
        session.send(body.message, {
          auth: authFor("reply", body.marker),
        }),
      );

      return Response.json({ ok: true, anchorToken, sessionId: session.id });
    }),
  ],
  events: {
    "turn.started"(event, channel) {
      channel.state.turnIds.push(event.turnId);
    },
    "message.completed"(event, channel) {
      channel.state.completedTurns += 1;
      channel.state.completedMessages.push(event.message ?? "");

      const anchorToken = channel.state.anchorToken;
      const continuation = channel.continuation;
      if (
        anchorToken !== null &&
        continuation !== undefined &&
        !continuation.token.endsWith(`:${anchorToken}`)
      ) {
        continuation.alias(anchorToken);
      }
    },
  },
});
