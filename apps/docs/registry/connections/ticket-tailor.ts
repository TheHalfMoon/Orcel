import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.tickettailor.ai/mcp",
  description: "Ticket Tailor: events, tickets, and orders.",
  auth: connect("ticket-tailor"),
});
