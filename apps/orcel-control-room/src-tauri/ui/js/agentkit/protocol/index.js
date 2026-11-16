// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/index.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Orcel changes: AgentKit's thread/run/message model, its approval,
// connection-request, queue, upload and action types, and every input type
// that starts, resumes, cancels or answers anything are not taken. What
// remains is the envelope idea (versioned frames, typed errors, ordered
// events with a sequence) bound to the shapes orceld serves in
// docs/orcel/implementation-readiness/protocol/ORCEL_APP_API_1.md.
// The Control Room is a read-only client: no type here can carry a request
// that submits work or answers, mints or forwards an approval.
export { APP_API_PROTOCOL, APP_API_SUPPORTED_PROTOCOLS, MAX_FRAME_BYTES, isAppApiProtocol, } from "./version.js";
/**
 * The only methods this client sends. Every one is read-only in orceld.
 * The list is closed: the client refuses any other name before a byte is
 * written, so nothing here can submit, approve, mint, stop or write.
 */
export const READ_METHODS = [
    "status.get",
    "capabilities.get",
    "events.subscribe",
];
/** Read-only names orceld reserves; it answers METHOD_UNAVAILABLE today. */
export const RESERVED_READ_METHODS = ["devices.list"];
export function isReadMethod(value) {
    return READ_METHODS.includes(value);
}
export const APP_API_ERROR_CODES = [
    "INVALID_REQUEST",
    "UNSUPPORTED_VERSION",
    "UNKNOWN_METHOD",
    "METHOD_UNAVAILABLE",
    "FRAME_TOO_LARGE",
    "BUSY",
    "INTERNAL",
];
export { AppApiProtocolError, AppApiValidationError, isAppApiProtocolError, } from "./errors.js";
export { encodeRequest, parseCapabilities, parseEvent, parseServerFrame, parseSnapshotData, parseStatus, parseSubscribeAck, } from "./validation.js";
