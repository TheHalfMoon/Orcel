import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.sentry.dev/mcp",
  description: "Sentry: search, query, and debug errors and issues.",
  auth: connect("sentry"),
});
