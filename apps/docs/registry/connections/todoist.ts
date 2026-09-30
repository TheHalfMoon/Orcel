import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://ai.todoist.net/mcp",
  description: "Todoist: search, complete, and manage tasks.",
  auth: connect("todoist"),
});
