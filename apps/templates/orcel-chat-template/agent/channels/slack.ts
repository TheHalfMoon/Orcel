import { getToken } from "@vercel/connect";
import { vercelOidc } from "@orcel/orcel/channels/auth";
import { slackChannel } from "@orcel/orcel/channels/slack";

// SLACK_CONNECTOR is the UID returned by `vercel connect create slack`.
// For local setup, create a connector with:
// `vercel connect create slack --name orcel-chat-template --triggers`.
const slackConnector = process.env.SLACK_CONNECTOR ?? "slack/orcel-chat-template";

export default slackChannel({
  credentials: {
    botToken: () => getToken(slackConnector, { subject: { type: "app" } }),
    webhookVerifier: vercelOidc(),
  },
  uploadPolicy: "disabled",
});
