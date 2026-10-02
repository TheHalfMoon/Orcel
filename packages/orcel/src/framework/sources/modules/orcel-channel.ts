import { localDev, placeholderAuth, vercelOidc } from "#public/channels/auth.js";
import { orcelChannel } from "#orcel-channel/index.js";

export default function createDefaultOrcelChannel() {
  return orcelChannel({ auth: [vercelOidc(), localDev(), placeholderAuth()] });
}
