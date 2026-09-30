import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://coda.io/apis/mcp",
  description: "Coda: create, search, and update docs and tables.",
  auth: connect("coda"),
});
