import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://netlify-mcp.netlify.app/mcp",
  description: "Netlify: create, deploy, manage, and secure sites.",
  auth: connect("netlify"),
});
