import type { AuthFn } from "kaf/channels/auth";
import { auth } from "./auth";
import { getPasswordSessionFromHeaders } from "./password-auth";
import { getSetupStatus } from "./setup";

export const betterAuthKafAuth: AuthFn<Request> = async (request) => {
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

export const passwordKafAuth: AuthFn<Request> = async (request) => {
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
      email: "local@kaf.dev",
      name: "kaf user",
    },
    authenticator: "password",
    issuer: "kaf-chat-template",
    principalId: "kaf-chat-user",
    principalType: "user",
    subject: "kaf-chat-user",
  };
};
