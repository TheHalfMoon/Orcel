import { defineAgent, defineDynamic } from "@orcel/orcel";
import { mockModel } from "@orcel/orcel/evals";
import { playScript } from "@orcel-e2e/config/mock-script";

const workerModel = mockModel({
  modelId: "nested-approval-worker",
  respond(request) {
    const authorization = request.userMessages.some((message) =>
      message.includes("Authorize Alice's release checklist."),
    );
    return authorization
      ? playScript(
          request,
          [{ id: "authorize", name: "authorization_gate", input: () => ({}) }],
          () => "NESTED-AUTHORIZED",
        )
      : playScript(
          request,
          [
            { id: "first", name: "first_gate" },
            { id: "second", name: "second_gate" },
          ],
          () => "NESTED-APPROVED",
        );
  },
});

export default defineAgent({
  description: "Collects Alice's or Bob's release checklist approvals or authorization.",
  model: defineDynamic({
    events: {
      "step.started": () => ({ model: workerModel, modelContextWindowTokens: 1_000_000 }),
    },
  }),
});
