import { linearChannel } from "@orcel/orcel/channels/linear";

export default linearChannel({
  credentials: {
    accessToken: () => process.env.LINEAR_AGENT_ACCESS_TOKEN!,
    webhookSecret: () => process.env.LINEAR_WEBHOOK_SECRET!,
  },
});
