import { getToken } from "@vercel/connect";
import { vercelOidc } from "kaf/channels/auth";
import { slackChannel } from "kaf/channels/slack";

// SLACK_CONNECTOR is the UID returned by `vercel connect create slack`.
// For local setup, create a connector with:
// `vercel connect create slack --name kaf-chat-template --triggers`.
const slackConnector = process.env.SLACK_CONNECTOR ?? "slack/kaf-chat-template";

export default slackChannel({
  credentials: {
    botToken: () => getToken(slackConnector, { subject: { type: "app" } }),
    webhookVerifier: vercelOidc(),
  },
  uploadPolicy: "disabled",
});
