import { localDev, placeholderAuth, vercelOidc } from "#public/channels/auth.js";
import { kafChannel } from "#kaf-channel/index.js";

export default function createDefaultKafChannel() {
  return kafChannel({ auth: [vercelOidc(), localDev(), placeholderAuth()] });
}
