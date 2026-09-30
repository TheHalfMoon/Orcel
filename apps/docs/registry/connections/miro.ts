import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.miro.com/",
  description: "Miro: read and create content on boards.",
  auth: connect("miro"),
});
