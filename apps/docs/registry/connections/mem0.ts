import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.mem0.ai/mcp",
  description: "Mem0: store and retrieve persistent agent memory.",
  auth: connect("mem0"),
});
