import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.make.com",
  description: "Make: run scenarios and manage automations.",
  auth: connect("make"),
});
