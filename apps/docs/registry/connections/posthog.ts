import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.posthog.com/mcp",
  description: "PostHog: insights, events, and feature flags.",
  auth: connect("posthog"),
});
