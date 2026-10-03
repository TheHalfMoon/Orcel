import type { AuthFn } from "@orcel/orcel/channels/auth";
import { orcelChannel } from "@orcel/orcel/channels/orcel";
import type { SessionAuthContext } from "@orcel/orcel/context";
import { authenticateWorkspaceMember } from "../lib/workspace";

const PRINCIPAL_A = "Bearer e2e-create-once-a";
const PRINCIPAL_B = "Bearer e2e-create-once-b";

function principal(issuer: string): SessionAuthContext {
  return {
    attributes: {},
    authenticator: "e2e-create-once",
    issuer,
    principalId: "shared-principal-id",
    principalType: "user",
    subject: "shared-subject",
  };
}

const authenticateA: AuthFn<Request> = (request) =>
  request.headers.get("authorization") === PRINCIPAL_A ? principal("issuer-a") : null;
const authenticateB: AuthFn<Request> = (request) =>
  request.headers.get("authorization") === PRINCIPAL_B ? principal("issuer-b") : null;
const authenticateMember: AuthFn<Request> = (request) =>
  authenticateWorkspaceMember(request.headers.get("authorization"));
const authenticateEvalDriver: AuthFn<Request> = () => principal("eval-driver");

export default orcelChannel({
  auth: [authenticateA, authenticateB, authenticateMember, authenticateEvalDriver],
});
