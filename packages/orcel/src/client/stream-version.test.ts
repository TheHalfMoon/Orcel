import { describe, expect, it } from "vitest";

import { readMessageStreamVersion } from "#client/stream-version.js";
import { ORCEL_STREAM_VERSION_HEADER } from "#protocol/message.js";

describe("readMessageStreamVersion", () => {
  it.each(["21", "22", "23", "24", "25", "26"] as const)("accepts stream version %s", (version) => {
    expect(readMessageStreamVersion(new Headers({ [ORCEL_STREAM_VERSION_HEADER]: version }))).toBe(
      version,
    );
  });

  it("rejects a missing version", () => {
    expect(() => readMessageStreamVersion(new Headers())).toThrow(
      `Missing ${ORCEL_STREAM_VERSION_HEADER} response header.`,
    );
  });

  it("rejects an unsupported version", () => {
    expect(() =>
      readMessageStreamVersion(new Headers({ [ORCEL_STREAM_VERSION_HEADER]: "27" })),
    ).toThrow("Unsupported message stream version: 27.");
  });
});
