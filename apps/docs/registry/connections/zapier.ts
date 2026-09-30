import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.zapier.com/api/v1/connect",
  description: "Zapier: run and manage automations across apps.",
  auth: connect("zapier"),
});
