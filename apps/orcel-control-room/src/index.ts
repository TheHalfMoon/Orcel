// @orcel/control-room: the headless Control Room client (CR-02). It reads
// orceld's app API (orcel-app-api/1) and renders nothing; the UI is CR-03.
export * from "./agentkit/protocol/index.js";
export * from "./agentkit/client/index.js";
export * from "./agentkit/transport/orceld-transport.js";
export { LineDecoder } from "./agentkit/transport/framing.js";
