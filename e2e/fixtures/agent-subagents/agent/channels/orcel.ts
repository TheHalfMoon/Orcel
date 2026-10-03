import type { AuthFn } from "@orcel/orcel/channels/auth";
import { orcelChannel } from "@orcel/orcel/channels/orcel";
import type { SessionAuthContext } from "@orcel/orcel/context";

/**
 * Authored orcel channel for the remote principal-forwarding eval. Four
 * deterministic principals, no injected env (the deployment is deliberately
 * open — fixture-only; do not pattern production channels off this):
 *
 * - The `remote-loopback` hop authenticates with a fixture authorization and runs as
 *   the `router-app` service principal — the trusted forwarder.
 * - Bob and the observer each have a fixture authorization, so the eval can continue
 *   Alice's child as two distinct callers. Bob has his own user grant; the
 *   observer deliberately has none.
 * - Every other caller (the local eval driver is anonymous; the Vercel one
 *   may carry ambient OIDC) falls through to Alice's fixed user principal.
 */
const ROUTER_AUTHORIZATION = "Bearer e2e-workspace-label-router";
const BOB_AUTHORIZATION = "Bearer e2e-workspace-label-bob";
const OBSERVER_AUTHORIZATION = "Bearer e2e-workspace-label-observer";

function createFixtureUserPrincipal(principalId: string): SessionAuthContext {
  return {
    attributes: {},
    authenticator: "e2e-fixture",
    issuer: "e2e",
    principalId,
    principalType: "user",
    subject: principalId,
  };
}

const authenticateRouter: AuthFn<Request> = (request) => {
  if (request.headers.get("authorization") !== ROUTER_AUTHORIZATION) return null;
  return {
    attributes: {},
    authenticator: "e2e-bearer",
    principalId: "router-app",
    principalType: "service",
  };
};

const authenticateBob: AuthFn<Request> = (request) => {
  if (request.headers.get("authorization") !== BOB_AUTHORIZATION) return null;
  return createFixtureUserPrincipal("e2e-user-2");
};

const authenticateObserver: AuthFn<Request> = (request) => {
  if (request.headers.get("authorization") !== OBSERVER_AUTHORIZATION) return null;
  return createFixtureUserPrincipal("e2e-observer");
};

const authenticateDefaultUser: AuthFn<Request> = () => createFixtureUserPrincipal("e2e-user");

export default orcelChannel({
  auth: [authenticateRouter, authenticateBob, authenticateObserver, authenticateDefaultUser],
  trustedForwarders: (forwarder) => forwarder.principalId === "router-app",
});
