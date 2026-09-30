import type { AuthFn } from "kaf/channels/auth";
import { kafChannel } from "kaf/channels/kaf";
import { vercelOidc } from "kaf/channels/auth";

type AppUser = {
  email: string;
  id: string;
  name: string;
};

type AppSession = {
  user?: AppUser;
};

const appSession: AuthFn<Request> = async (request) => {
  const origin = process.env.BETTER_AUTH_URL?.trim();
  if (!origin) return null;

  const response = await fetch(new URL("/api/auth/get-session", origin), {
    headers: { cookie: request.headers.get("cookie") ?? "" },
  });
  if (!response.ok) return null;

  const session = (await response.json()) as AppSession | null;
  if (!session?.user) return null;

  return {
    attributes: {
      email: session.user.email,
      name: session.user.name,
    },
    authenticator: "app",
    issuer: "app",
    principalId: session.user.id,
    principalType: "user",
  };
};

export default kafChannel({
  auth: [appSession, vercelOidc()],
});
