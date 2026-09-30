import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://tellme.embat.io/mcp",
  description: "Embat: cash, debt, payments, and accounting.",
  auth: connect("embat"),
});
