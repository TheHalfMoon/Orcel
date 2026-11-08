import assert from "node:assert/strict";
import { test } from "node:test";
import { uploadFile, type UploadPage } from "./upload.js";
import { NavigationError } from "../worker.js";

interface Element {
  tag: string;
  type?: string;
  covered?: boolean;
}

/// A page whose refs name elements; records the files set.
function page(refs: Record<string, Element[]>) {
  const set: Array<{ path: string }> = [];
  const located = (matches: Element[]): Record<string, unknown> => ({
    and: (other: { css: string }) =>
      located(other.css === 'input[type="file" i]' ? matches.filter((e) => e.tag === "input" && (e.type ?? "").toLowerCase() === "file") : []),
    count: async () => matches.length,
    setInputFiles: async (path: string) => {
      if (matches[0]?.covered) {
        throw Object.assign(new Error("Call log:\n  - attempting click action\n    - <div>cover</div> intercepts pointer events"), { name: "TimeoutError" });
      }
      set.push({ path });
    }
  });
  const stub = {
    locator: (selector: string) => (selector.startsWith("aria-ref=") ? located(refs[selector.slice("aria-ref=".length)] ?? []) : { css: selector }),
    mainFrame: () => ({ getByRole: () => located([]) })
  };
  return { stub: stub as unknown as UploadPage, set };
}

const reason = (expected: string) => (error: unknown) => error instanceof NavigationError && error.reason === expected;

test("BR-03 the staged file is set on the approved file input only", async () => {
  const { stub, set } = page({
    e1: [{ tag: "input", type: "file" }],
    e2: [{ tag: "button" }],
    e3: [{ tag: "input", type: "text" }],
    e4: [{ tag: "input", type: "FILE", covered: true }]
  });
  await uploadFile(stub, "e1", "C:\\staging\\up-1\\report.txt");
  assert.deepEqual(set, [{ path: "C:\\staging\\up-1\\report.txt" }]);
  for (const ref of ["e2", "e3"]) {
    await assert.rejects(uploadFile(stub, ref, "C:\\staging\\up-1\\report.txt"), reason("denied"), ref);
  }
  await assert.rejects(uploadFile(stub, "e9", "C:\\staging\\up-1\\report.txt"), reason("stale"));
  await assert.rejects(uploadFile(stub, "e4", "C:\\staging\\up-1\\report.txt"), reason("occluded"));
  assert.equal(set.length, 1);
});
