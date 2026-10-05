import { orcelChannel } from "@orcel/orcel/channels/orcel";
import { localDev, type AuthFn, vercelOidc } from "@orcel/orcel/channels/auth";
import { auth } from "@/lib/auth";

const betterAuthSession: AuthFn<Request> = async (request) => {
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session) return null;

  const attributes: Record<string, string> = {
    email: session.user.email,
    name: session.user.name,
  };
  if (session.user.image) {
    attributes.picture = session.user.image;
  }

  return {
    attributes,
    authenticator: "better-auth:vercel",
    principalId: session.user.id,
    principalType: "user",
  };
};

export default orcelChannel({
  auth: [betterAuthSession, vercelOidc(), localDev()],
});
