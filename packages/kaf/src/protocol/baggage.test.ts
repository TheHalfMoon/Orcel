import { describe, expect, it } from "vitest";

import {
  readBaggageMember,
  readForwardedAudienceBaggage,
  readForwardedParentSessionBaggage,
  writeForwardedAudienceBaggage,
  writeForwardedParentSessionBaggage,
} from "#protocol/baggage.js";

const PUBLIC_OUTPUTS = {
  ceiling: { recordInputs: false, recordOutputs: true },
  originAudience: "public",
} as const;
const PARENT = {
  callId: "call-1",
  rootSessionId: "root-session",
  sessionId: "parent-session",
  turn: { id: "turn-1", sequence: 2 },
} as const;

describe("baggage member parsing", () => {
  it.each(["kaf.audience", "kaf.conversation.id"])("uses the same wire rules for %s", (key) => {
    expect(readBaggageMember(`${key} = public%2Fone+two ; flag ; source=a%3Db`, key)).toEqual({
      value: "public/one+two",
      properties: [{ key: "flag" }, { key: "source", value: "a=b" }],
    });
    expect(readBaggageMember(`${key}=a,${key}=a`, key)).toBe("malformed");
    expect(readBaggageMember(`${key}=%ZZ`, key)).toBe("malformed");
    expect(readBaggageMember(`${key}=value\n`, key)).toBe("malformed");
    expect(readBaggageMember(`${key}=value,vendor=${"a".repeat(8192)}`, key)).toBe("malformed");
    expect(readBaggageMember(`${key}=%FF`, key)).toEqual({ value: "\ufffd", properties: [] });
    expect(readBaggageMember(`${key}=%EF%BB%BFvalue`, key)).toEqual({
      value: "\ufeffvalue",
      properties: [],
    });
  });

  it("decodes audience and property values before applying the policy schema", () => {
    expect(readForwardedAudienceBaggage("kaf.audience=%70ublic;ceiling=%691o0")).toEqual({
      originAudience: "public",
      ceiling: { recordInputs: true, recordOutputs: false },
    });
  });
});

describe("readForwardedAudienceBaggage", () => {
  it.each([
    ["public", true, true],
    ["private", true, false],
    ["unknown", false, false],
  ] as const)("reads a %s origin audience with its ceiling", (originAudience, inputs, outputs) => {
    expect(
      readForwardedAudienceBaggage(
        `vendor=value,kaf.audience=${originAudience};ceiling=i${inputs ? "1" : "0"}o${outputs ? "1" : "0"}`,
      ),
    ).toEqual({
      ceiling: { recordInputs: inputs, recordOutputs: outputs },
      originAudience,
    });
  });

  it("accepts W3C optional whitespace around separators", () => {
    expect(
      readForwardedAudienceBaggage(
        "vendor=value\t,\t kaf.audience \t=\t private \t;\t ceiling \t=\t i1o0 \t",
      ),
    ).toEqual({
      ceiling: { recordInputs: true, recordOutputs: false },
      originAudience: "private",
    });
  });

  it.each([null, "vendor=value", "kaf.capture=i1o1"])('returns absent for "%s"', (value) => {
    expect(readForwardedAudienceBaggage(value)).toBe("absent");
  });

  it.each([
    "kaf.audience=public",
    "kaf.audience=private",
    "kaf.audience=public,kaf.audience=public;ceiling=i1o1",
    "kaf.audience=public;ceiling=i1o1,kaf.audience=private;ceiling=i0o0",
    "kaf.audience=public;ceiling=i1o1;vendor=yes",
    "kaf.audience=public;vendor=yes",
    "kaf.audience=public;ceiling=i1o1;ceiling=i0o0",
    "kaf.audience=public;ceiling=i2o1",
    "kaf.audience=public;ceiling=o1i1",
    "kaf.audience=public;ceiling=drop",
    "kaf.audience=everyone;ceiling=i1o1",
    "kaf.audience=public;ceiling",
    "kaf.audience=public;bad property=i1o1",
    "kaf.audience",
    "kaf.audience=public;ceiling=i1o1\n",
    "kaf.audience=public;\vceiling=i1o1",
    "kaf.audience=public;\fceiling=i1o1",
    "kaf.audience=public;\u00a0ceiling=i1o1",
  ])("fails closed for malformed Kaf baggage %s", (value) => {
    expect(readForwardedAudienceBaggage(value)).toBe("malformed");
  });
});

describe("writeForwardedAudienceBaggage", () => {
  it("preserves the assertion at the byte limit and rejects overflow", () => {
    const assertion = "kaf.audience=public;ceiling=i0o1";
    const baggage = `vendor=${"a".repeat(8192 - assertion.length - "vendor=,".length)}`;
    const result = writeForwardedAudienceBaggage(baggage, PUBLIC_OUTPUTS);
    expect(new TextEncoder().encode(result).byteLength).toBe(8192);
    expect(readForwardedAudienceBaggage(result!)).toEqual(PUBLIC_OUTPUTS);
    expect(() => writeForwardedAudienceBaggage(`${baggage}a`, PUBLIC_OUTPUTS)).toThrow(
      "Cannot forward baggage: header exceeds 8192 bytes",
    );
    expect(() => writeForwardedAudienceBaggage(`${baggage}\u00e9`, PUBLIC_OUTPUTS)).toThrow(
      "Cannot forward baggage: header exceeds 8192 bytes",
    );
  });

  it("preserves unrelated entries and replaces authored Kaf assertions", () => {
    expect(
      writeForwardedAudienceBaggage(
        "first=1,kaf.audience=private;ceiling=i1o1,second=2",
        PUBLIC_OUTPUTS,
      ),
    ).toBe("first=1,second=2,kaf.audience=public;ceiling=i0o1");
    expect(
      writeForwardedAudienceBaggage("kaf.audience=public,kaf.capture=i1o1", PUBLIC_OUTPUTS),
    ).toBe("kaf.capture=i1o1,kaf.audience=public;ceiling=i0o1");
  });

  it("removes malformed authored Kaf audience members", () => {
    expect(writeForwardedAudienceBaggage("kaf.audience,vendor=value", PUBLIC_OUTPUTS)).toBe(
      "vendor=value,kaf.audience=public;ceiling=i0o1",
    );
    expect(
      writeForwardedAudienceBaggage("kaf.audience;property=x,vendor=value", PUBLIC_OUTPUTS),
    ).toBe("vendor=value,kaf.audience=public;ceiling=i0o1");
  });

  it("removes authored Kaf assertions when there is no sampled record decision", () => {
    expect(
      writeForwardedAudienceBaggage("kaf.audience=public;ceiling=i1o1,vendor=value", undefined),
    ).toBe("vendor=value");
    expect(
      writeForwardedAudienceBaggage("kaf.audience=public;ceiling=i1o1", undefined),
    ).toBeUndefined();
  });
});

describe("forwarded parent session baggage", () => {
  it("round-trips lineage while preserving unrelated members", () => {
    const baggage = writeForwardedParentSessionBaggage("vendor=value", PARENT);
    expect(baggage).toContain("vendor=value");
    expect(readForwardedParentSessionBaggage(baggage!)).toEqual(PARENT);
  });

  it.each([null, "vendor=value"])("returns absent for %s", (value) => {
    expect(readForwardedParentSessionBaggage(value)).toBe("absent");
  });

  it.each([
    "kaf.parent_session=not-json",
    `kaf.parent_session=${encodeURIComponent(JSON.stringify({ ...PARENT, callId: "" }))}`,
    `kaf.parent_session=${encodeURIComponent(JSON.stringify({ ...PARENT, turn: { id: "turn-1" } }))}`,
    `kaf.parent_session=${encodeURIComponent(JSON.stringify(PARENT))};extra=yes`,
  ])("rejects malformed lineage %s", (value) => {
    expect(readForwardedParentSessionBaggage(value)).toBe("malformed");
  });
});
