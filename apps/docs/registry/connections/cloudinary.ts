import { connect } from "@vercel/connect/kaf";
import { defineMcpClientConnection } from "kaf/connections";

export default defineMcpClientConnection({
  url: "https://asset-management.mcp.cloudinary.com/sse",
  description: "Cloudinary: manage, transform, and deliver image and video assets.",
  auth: connect("cloudinary"),
});
