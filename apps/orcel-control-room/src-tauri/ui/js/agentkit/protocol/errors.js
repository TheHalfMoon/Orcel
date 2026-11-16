// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/errors.ts and the AgentProtocolValidationError
// class of packages/agentkit/src/protocol/validation.ts (MIT, Builder.io;
// notice in docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Orcel changes: the error carries orceld's error body ({code, message}); the
// capability/operation/abort/version constructors of AgentKit are not taken
// because orceld reports those cases itself.
/** A server frame or a local value that does not match orcel-app-api/1. */
export class AppApiValidationError extends Error {
    path;
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "AppApiValidationError";
        this.path = path;
    }
}
/** An error frame orceld sent, or one the client raises for the same codes. */
export class AppApiProtocolError extends Error {
    protocolError;
    code;
    constructor(protocolError) {
        super(`${protocolError.code}: ${protocolError.message}`);
        this.protocolError = protocolError;
        this.name = "AppApiProtocolError";
        this.code = protocolError.code;
    }
}
export function isAppApiProtocolError(value) {
    return value instanceof AppApiProtocolError;
}
