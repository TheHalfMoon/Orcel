import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp-server.egnyte.com/mcp",
  description: "Egnyte: search, access, and analyze governed content.",
  auth: connect("egnyte"),
});
