import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.manufact.com/mcp",
  description: "Manufact: deploy and monitor MCP servers.",
  auth: connect("manufact"),
});
