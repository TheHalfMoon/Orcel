import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://api.brex.com/mcp",
  description: "Brex: expenses, cards, budgets, and cash.",
  auth: connect("brex"),
});
