import { orcelChannel } from "orcel/channels/orcel";
import { localDev, vercelOidc } from "orcel/channels/auth";
import { betterAuthOrcelAuth, passwordOrcelAuth } from "../../apps/web/lib/orcel-auth";

export default orcelChannel({
  auth: [betterAuthOrcelAuth, passwordOrcelAuth, vercelOidc(), localDev()],
  uploadPolicy: "disabled",
});
