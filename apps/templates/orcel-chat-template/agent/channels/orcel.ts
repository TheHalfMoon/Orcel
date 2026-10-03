import { orcelChannel } from "@orcel/orcel/channels/orcel";
import { localDev, vercelOidc } from "@orcel/orcel/channels/auth";
import { betterAuthOrcelAuth, passwordOrcelAuth } from "../../apps/web/lib/orcel-auth";

export default orcelChannel({
  auth: [betterAuthOrcelAuth, passwordOrcelAuth, vercelOidc(), localDev()],
  uploadPolicy: "disabled",
});
