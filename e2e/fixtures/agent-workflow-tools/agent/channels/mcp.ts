import { none } from "kaf/channels/auth";
import { mcpChannel } from "kaf/channels/mcp";

// Fixture-only public access so the MCP eval needs no injected credentials.
export default mcpChannel({ auth: none() });
