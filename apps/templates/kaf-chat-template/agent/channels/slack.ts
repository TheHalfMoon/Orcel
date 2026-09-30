import { connectSlackCredentials } from "@vercel/connect/kaf";
import { slackChannel } from "kaf/channels/slack";

// SLACK_CONNECTOR is the UID returned by `vercel connect create slack`.
// For local setup, create a connector with:
// `vercel connect create slack --name kaf-chat-template --triggers`.
const slackConnector = process.env.SLACK_CONNECTOR ?? "slack/kaf-chat-template";

export default slackChannel({
  credentials: connectSlackCredentials(slackConnector),
  uploadPolicy: "disabled",
});
