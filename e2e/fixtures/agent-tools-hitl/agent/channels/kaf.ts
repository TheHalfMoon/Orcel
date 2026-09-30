import { kafChannel } from "kaf/channels/kaf";

/** Fixture-only authentication for interactive authorization evals. */
export default kafChannel({
  auth: (request) => {
    const principalId = request.headers.get("x-kaf-fixture-user") ?? "e2e-approval-responder";
    return {
      attributes: {
        fixture: "authorized-response",
        model: request.headers.get("x-kaf-fixture-model") ?? "default",
      },
      authenticator: "e2e-fixture",
      issuer: "e2e",
      principalId,
      principalType: "user",
      subject: principalId,
    };
  },
});
