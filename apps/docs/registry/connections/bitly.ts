import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://api-ssl.bitly.com/v4/mcp",
  description: "Bitly: shorten links, generate QR Codes, and track link performance.",
  auth: connect("bitly"),
});
