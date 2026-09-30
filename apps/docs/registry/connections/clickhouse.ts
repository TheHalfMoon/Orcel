import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://mcp.clickhouse.cloud/mcp",
  description: "ClickHouse Cloud: query and explore databases and tables.",
  auth: connect("clickhouse"),
});
