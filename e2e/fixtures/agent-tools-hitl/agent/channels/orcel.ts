import { orcelChannel } from "@orcel/orcel/channels/orcel";

/** Fixture-only authentication for interactive authorization evals. */
export default orcelChannel({
  auth: (request) => {
    const principalId = request.headers.get("x-orcel-fixture-user") ?? "e2e-approval-responder";
    return {
      attributes: {
        fixture: "authorized-response",
        model: request.headers.get("x-orcel-fixture-model") ?? "default",
      },
      authenticator: "e2e-fixture",
      issuer: "e2e",
      principalId,
      principalType: "user",
      subject: principalId,
    };
  },
});
