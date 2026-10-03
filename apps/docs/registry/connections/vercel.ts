import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.vercel.com",
  description: "Vercel: manage projects and deployments, inspect logs, and search documentation.",
  auth: connect("vercel"),
});
