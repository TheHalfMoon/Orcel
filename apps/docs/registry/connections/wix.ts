import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.wix.com/mcp",
  description: "Wix: manage and build sites and apps.",
  auth: connect("wix"),
});
