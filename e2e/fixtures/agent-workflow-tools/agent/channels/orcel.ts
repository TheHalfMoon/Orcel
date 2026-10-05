import { orcelChannel } from "@orcel/orcel/channels/orcel";

export default orcelChannel({
  auth: (request) => {
    const forwarded = request.headers.get("x-orcel-forwarded-principal-id");
    const principalId = forwarded ?? "workflow-e2e-user";
    return {
      attributes: { fixture: "workflow-agent-probes" },
      authenticator: "e2e-fixture",
      issuer: "e2e",
      principalId,
      principalType: "user",
      subject: principalId,
    };
  },
});
