import { connect } from "@vercel/connect/eve";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.supabase.com/mcp",
  description: "Supabase: databases, authentication, and storage.",
  auth: connect("supabase"),
});
