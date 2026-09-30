import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.stripe.com",
  description: "Stripe: payments, customers, billing, and financial infrastructure.",
  auth: connect("stripe"),
});
