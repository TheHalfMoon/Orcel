import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.tickettailor.ai/mcp",
  description: "Ticket Tailor: events, tickets, and orders.",
  auth: connect("ticket-tailor"),
});
