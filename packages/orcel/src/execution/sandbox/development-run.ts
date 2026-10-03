import { randomUUID } from "node:crypto";

export const ORCEL_DEVELOPMENT_SANDBOX_RUN_ID_ENV = "ORCEL_DEVELOPMENT_SANDBOX_RUN_ID";
export const ORCEL_DEVELOPMENT_SANDBOX_METADATA_PATH_TAG = "orcel.metadataPath";
export const ORCEL_DEVELOPMENT_SANDBOX_RUN_ID_TAG = "devRunId";

export function createDevelopmentSandboxRunId(): string {
  return randomUUID();
}

export function getDevelopmentSandboxRunId(): string | undefined {
  const value = process.env[ORCEL_DEVELOPMENT_SANDBOX_RUN_ID_ENV];
  return value === undefined || value.trim() === "" ? undefined : value;
}

export function withDevelopmentSandboxTags(
  tags: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> | undefined {
  const runId = getDevelopmentSandboxRunId();
  if (runId === undefined) {
    return tags;
  }
  return {
    ...tags,
    [ORCEL_DEVELOPMENT_SANDBOX_RUN_ID_TAG]: runId,
  };
}

export function withDevelopmentSandboxMetadataPathTag(
  tags: Readonly<Record<string, string>> | undefined,
  metadataPath: string,
): Readonly<Record<string, string>> | undefined {
  if (getDevelopmentSandboxRunId() === undefined) {
    return tags;
  }
  return {
    ...tags,
    [ORCEL_DEVELOPMENT_SANDBOX_METADATA_PATH_TAG]: metadataPath,
  };
}
