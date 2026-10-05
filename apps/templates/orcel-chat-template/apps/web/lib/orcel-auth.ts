import type { AuthFn } from "@orcel/orcel/channels/auth";
import { auth } from "./auth";
import { getPasswordSessionFromHeaders } from "./password-auth";
import { getSetupStatus } from "./setup";

export const betterAuthOrcelAuth: AuthFn<Request> = async (request) => {
  const setupStatus = await getSetupStatus();

  if (!setupStatus.appReady || setupStatus.authMode !== "vercel") {
    return null;
  }

  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session?.user) {
    return null;
  }

  return {
    attributes: {
      email: session.user.email,
      name: session.user.name,
    },
    authenticator: "better-auth",
    issuer: "better-auth",
    principalId: session.user.id,
    principalType: "user",
    subject: session.user.email,
  };
};

export const passwordOrcelAuth: AuthFn<Request> = async (request) => {
  const setupStatus = await getSetupStatus();

  if (
    !setupStatus.appReady ||
    setupStatus.authMode !== "password" ||
    !getPasswordSessionFromHeaders(request.headers)
  ) {
    return null;
  }

  return {
    attributes: {
      email: "local@orcel.dev",
      name: "orcel user",
    },
    authenticator: "password",
    issuer: "orcel-chat-template",
    principalId: "orcel-chat-user",
    principalType: "user",
    subject: "orcel-chat-user",
  };
};
