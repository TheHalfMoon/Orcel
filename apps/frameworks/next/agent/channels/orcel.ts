import { type AuthFn, localDev, vercelOidc } from "orcel/channels/auth";
import { orcelChannel } from "orcel/channels/orcel";
import { getAuthJsSession } from "@/lib/auth";

function authjsSession(): AuthFn<Request> {
  return async (request) => {
    const session = await getAuthJsSession(request);
    if (!session) return null;

    const attributes: Record<string, string> = {
      providerId: session.providerId,
    };
    if (session.profile.email) {
      attributes.email = session.profile.email;
    }
    if (session.profile.name) {
      attributes.name = session.profile.name;
    }
    if (session.profile.image) {
      attributes.image = session.profile.image;
    }
    return {
      attributes,
      authenticator: "authjs",
      issuer: session.issuer,
      principalId: session.profile.sub,
      principalType: "user",
      subject: session.profile.sub,
    };
  };
}

export default orcelChannel({
  auth: [authjsSession(), vercelOidc(), localDev()],
});
