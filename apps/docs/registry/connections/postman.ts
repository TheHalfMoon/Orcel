import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.postman.com/minimal",
  description: "Postman: APIs, collections, and workspaces.",
  auth: connect("postman"),
});
