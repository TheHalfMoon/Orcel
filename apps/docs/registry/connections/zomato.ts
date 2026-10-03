import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp-server.zomato.com/mcp",
  description: "Zomato: food ordering and delivery.",
  auth: connect("zomato"),
});
