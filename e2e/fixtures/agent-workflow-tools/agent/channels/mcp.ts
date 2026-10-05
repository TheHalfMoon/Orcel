import { none } from "@orcel/orcel/channels/auth";
import { mcpChannel } from "@orcel/orcel/channels/mcp";

// Fixture-only public access so the MCP eval needs no injected credentials.
export default mcpChannel({ auth: none() });
