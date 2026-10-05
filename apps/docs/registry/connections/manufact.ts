import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.manufact.com/mcp",
  description: "Manufact: deploy and monitor MCP servers.",
  auth: connect("manufact"),
});
