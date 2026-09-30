import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp-server.zomato.com/mcp",
  description: "Zomato: food ordering and delivery.",
  auth: connect("zomato"),
});
