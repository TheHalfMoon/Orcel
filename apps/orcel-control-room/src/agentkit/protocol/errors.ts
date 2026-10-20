// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/errors.ts and the AgentProtocolValidationError
// class of packages/agentkit/src/protocol/validation.ts (MIT, Builder.io;
// notice in docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Orcel changes: the error carries orceld's error body ({code, message}); the
// capability/operation/abort/version constructors of AgentKit are not taken
// because orceld reports those cases itself.

import type { AppApiErrorBody } from "./index.js";

/** A server frame or a local value that does not match orcel-app-api/1. */
export class AppApiValidationError extends Error {
  public readonly path: string;

  public constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "AppApiValidationError";
    this.path = path;
  }
}

/** An error frame orceld sent, or one the client raises for the same codes. */
export class AppApiProtocolError extends Error {
  public readonly code: AppApiErrorBody["code"];

  public constructor(public readonly protocolError: AppApiErrorBody) {
    super(`${protocolError.code}: ${protocolError.message}`);
    this.name = "AppApiProtocolError";
    this.code = protocolError.code;
  }
}

export function isAppApiProtocolError(
  value: unknown,
): value is AppApiProtocolError {
  return value instanceof AppApiProtocolError;
}
