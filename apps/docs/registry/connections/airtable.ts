import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.airtable.com/mcp",
  description: "Airtable: bases, tables, and records.",
  auth: connect("airtable"),
});
