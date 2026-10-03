import { orcelChannel } from "@orcel/orcel/channels/orcel";

export default orcelChannel({
  auth: () => ({
    attributes: { fixture: "self-modification" },
    authenticator: "e2e-fixture",
    issuer: "e2e",
    principalId: "self-modification-e2e-user",
    principalType: "user",
    subject: "self-modification-e2e-user",
  }),
});
