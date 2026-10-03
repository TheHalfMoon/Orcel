import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.make.com",
  description: "Make: run scenarios and manage automations.",
  auth: connect("make"),
});
