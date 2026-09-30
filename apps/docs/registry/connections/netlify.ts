import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://netlify-mcp.netlify.app/mcp",
  description: "Netlify: create, deploy, manage, and secure sites.",
  auth: connect("netlify"),
});
