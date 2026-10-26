import assert from "node:assert/strict";
import { test } from "node:test";
import { approvedElement, type TargetPage } from "./targets.js";
import { NavigationError } from "../worker.js";

/// A page whose ref resolves to `refCount` elements and whose role locator
/// to `roleCount`; records the role queries.
function page(refCount: number, roleCount: number) {
  const queries: Array<{ role: string; name: unknown; exact: unknown }> = [];
  const stub = {
    locator: (selector: string) => ({ selector, count: async () => refCount }),
    mainFrame: () => ({
      getByRole: (role: string, options: { name: unknown; exact: unknown }) => {
        queries.push({ role, name: options.name, exact: options.exact });
        return { role, count: async () => roleCount };
      }
    })
  };
  return { stub: stub as unknown as TargetPage, queries };
}

const stale = (error: unknown) => error instanceof NavigationError && error.reason === "stale";

test("BR-01 a live ref is used as is, without a role query", async () => {
  const { stub, queries } = page(1, 0);
  const found = (await approvedElement(stub, "e5", { role: "link", name: "Annual review" })) as unknown as { selector: string };
  assert.equal(found.selector, "aria-ref=e5");
  assert.deepEqual(queries, []);
});

test("BR-01 a stale ref falls back to the one element with the exact approved role and name", async () => {
  const { stub, queries } = page(0, 1);
  const found = (await approvedElement(stub, "e5", { role: "link", name: "Annual review" })) as unknown as { role: string };
  assert.equal(found.role, "link");
  assert.deepEqual(queries, [{ role: "link", name: "Annual review", exact: true }]);
});

test("BR-01 no target, a frame ref, an empty name, no match or several matches are stale", async () => {
  for (const [ref, target, roleCount] of [
    ["e5", undefined, 1],
    ["f1e5", { role: "link", name: "Annual review" }, 1],
    ["e5", { role: "link", name: "" }, 1],
    ["e5", { role: "link", name: "Annual review" }, 0],
    ["e5", { role: "link", name: "Annual review" }, 2]
  ] as const) {
    const { stub } = page(0, roleCount);
    await assert.rejects(approvedElement(stub, ref, target), stale, `${ref} ${JSON.stringify(target)} ${roleCount}`);
  }
  // A ref that names several elements is not live either.
  const { stub } = page(2, 0);
  await assert.rejects(approvedElement(stub, "e5", { role: "link", name: "x" }), stale);
});
