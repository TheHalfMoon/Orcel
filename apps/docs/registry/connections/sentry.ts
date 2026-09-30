import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.sentry.dev/mcp",
  description: "Sentry: search, query, and debug errors and issues.",
  auth: connect("sentry"),
});
