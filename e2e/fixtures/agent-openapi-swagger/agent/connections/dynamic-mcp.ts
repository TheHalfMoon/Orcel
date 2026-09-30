import { defineDynamic, defineMcpClientConnection } from "kaf/connections";

export default defineDynamic({
  events: {
    "session.started": () =>
      defineMcpClientConnection({
        description: "Caller-specific dynamic MCP service.",
        url: "https://dynamic-mcp.example.invalid/mcp",
      }),
  },
});
