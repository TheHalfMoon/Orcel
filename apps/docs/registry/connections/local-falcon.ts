import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.localfalcon.com",
  description: "Local Falcon: local search rankings and AI visibility reports.",
  auth: connect("local-falcon"),
});
