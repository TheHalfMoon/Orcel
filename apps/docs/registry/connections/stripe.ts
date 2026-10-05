import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "@orcel/orcel/connections";

export default defineMcpClientConnection({
  url: "https://mcp.stripe.com",
  description: "Stripe: payments, customers, billing, and financial infrastructure.",
  auth: connect("stripe"),
});
