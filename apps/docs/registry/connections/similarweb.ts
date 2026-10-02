import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.similarweb.com",
  description: "Similarweb: web traffic, app, and market intelligence data.",
  auth: connect("similarweb"),
});
