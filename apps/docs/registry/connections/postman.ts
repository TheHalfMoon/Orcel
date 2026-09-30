import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.postman.com/minimal",
  description: "Postman: APIs, collections, and workspaces.",
  auth: connect("postman"),
});
