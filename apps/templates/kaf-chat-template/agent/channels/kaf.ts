import { kafChannel } from "kaf/channels/kaf";
import { localDev, vercelOidc } from "kaf/channels/auth";
import { betterAuthKafAuth, passwordKafAuth } from "../../apps/web/lib/kaf-auth";

export default kafChannel({
  auth: [betterAuthKafAuth, passwordKafAuth, vercelOidc(), localDev()],
  uploadPolicy: "disabled",
});
