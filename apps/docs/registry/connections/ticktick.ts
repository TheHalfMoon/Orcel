import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.ticktick.com",
  description: "TickTick: tasks, habits, and lists.",
  auth: connect("ticktick"),
});
