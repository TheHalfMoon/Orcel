import type { Nitro } from "nitro/types";
import { describe, expect, it } from "vitest";

import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";
import {
  applyKafCronHandlerRoute,
  createKafCronHandlerRoute,
} from "#internal/nitro/host/cron-handler-route.js";

// 32 random bytes encoded as base64url (no padding) → 43 characters.
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]{43}$/;

describe("createKafCronHandlerRoute", () => {
  it("returns a route under the kaf protocol prefix with a random base64url suffix", () => {
    const route = createKafCronHandlerRoute();

    expect(route.startsWith(`${KAF_ROUTE_PREFIX}/cron/`)).toBe(true);

    const suffix = route.slice(`${KAF_ROUTE_PREFIX}/cron/`.length);
    expect(suffix).toMatch(BASE64URL_PATTERN);
  });

  it("emits a unique route on every call", () => {
    const seen = new Set<string>();
    for (let index = 0; index < 100; index += 1) {
      seen.add(createKafCronHandlerRoute());
    }

    expect(seen.size).toBe(100);
  });
});

describe("applyKafCronHandlerRoute", () => {
  it("replaces the Vercel preset's default cron handler route", () => {
    const nitro = createNitroStub({ vercel: { cronHandlerRoute: "/_vercel/cron" } });

    applyKafCronHandlerRoute(nitro);

    expect(nitro.options.vercel?.cronHandlerRoute).not.toBe("/_vercel/cron");
    expect(nitro.options.vercel?.cronHandlerRoute?.startsWith(`${KAF_ROUTE_PREFIX}/cron/`)).toBe(
      true,
    );
  });

  it("populates the route even when the preset has not initialized one yet", () => {
    const nitro = createNitroStub({ vercel: {} });

    applyKafCronHandlerRoute(nitro);

    expect(nitro.options.vercel?.cronHandlerRoute?.startsWith(`${KAF_ROUTE_PREFIX}/cron/`)).toBe(
      true,
    );
  });

  it("is a no-op when the Vercel preset is not in use", () => {
    const nitro = createNitroStub({});

    applyKafCronHandlerRoute(nitro);

    expect(nitro.options.vercel).toBeUndefined();
  });
});

function createNitroStub(input: { vercel?: { cronHandlerRoute?: string } }): Nitro {
  return {
    options: {
      vercel: input.vercel,
    },
  } as unknown as Nitro;
}
