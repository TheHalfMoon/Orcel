import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.webflow.com/mcp",
  description: "Webflow: CMS items, pages, assets, and sites.",
  auth: connect("webflow"),
});
