import { describe, expect, it } from "vitest";
import { createCanonicalSitemap } from "./sitemap";

const sourceDate = new Date("2026-07-20T12:00:00.000Z");

const sources = [
  { pathname: "/" },
  { pathname: "/docs/getting-started", lastModified: sourceDate },
  { pathname: "/docs/getting-started", lastModified: new Date("2026-08-01") },
  { pathname: "/benchmarks" },
  { pathname: "/integrations" },
  { pathname: "/integrations/slack" },
  { pathname: "/templates" },
  { pathname: "/templates/kaf-chat-template" },
  { pathname: "/docs/channels" },
  { pathname: "/docs/getting-started.md" },
  { pathname: "/integrations?filter=channel" },
  { pathname: "/en/integrations/slack" },
  { pathname: "/llms.txt" },
  { pathname: "/api" },
  { pathname: "/unknown.xml" },
];

describe("createCanonicalSitemap", () => {
  it("includes each canonical public HTML route exactly once", () => {
    const sitemap = createCanonicalSitemap({
      excludedPathnames: ["/docs/channels"],
      origin: "https://github.com/TheHalfMoon/kaf",
      sources,
    });

    expect(sitemap.map(({ url }) => url)).toEqual([
      "https://github.com/TheHalfMoon/kaf/",
      "https://github.com/TheHalfMoon/kaf/benchmarks",
      "https://github.com/TheHalfMoon/kaf/docs/getting-started",
      "https://github.com/TheHalfMoon/kaf/integrations",
      "https://github.com/TheHalfMoon/kaf/integrations/slack",
      "https://github.com/TheHalfMoon/kaf/templates",
      "https://github.com/TheHalfMoon/kaf/templates/kaf-chat-template",
    ]);
  });

  it("excludes redirects, queries, locale aliases, machine routes, and errors", () => {
    const urls = createCanonicalSitemap({
      excludedPathnames: ["/docs/channels"],
      origin: "https://github.com/TheHalfMoon/kaf",
      sources,
    }).map(({ url }) => url);

    expect(urls).not.toEqual(
      expect.arrayContaining([
        expect.stringContaining("?"),
        expect.stringContaining("/en/"),
        expect.stringMatching(/\.(?:md|mdx|txt|xml)$/),
        "https://github.com/TheHalfMoon/kaf/docs/channels",
        "https://github.com/TheHalfMoon/kaf/api",
      ]),
    );
  });

  it("uses trustworthy source dates without build-time fallbacks", () => {
    const first = createCanonicalSitemap({ origin: "https://github.com/TheHalfMoon/kaf", sources });
    const second = createCanonicalSitemap({ origin: "https://github.com/TheHalfMoon/kaf", sources });
    const docsEntry = first.find(({ url }) => url.endsWith("/docs/getting-started"));
    const integrationEntry = first.find(({ url }) => url.endsWith("/integrations/slack"));

    expect(docsEntry?.lastModified).toEqual(sourceDate);
    expect(docsEntry?.lastModified).not.toBe(sourceDate);
    expect(integrationEntry).not.toHaveProperty("lastModified");
    expect(second).toEqual(first);
  });

  it("omits invalid source dates", () => {
    expect(
      createCanonicalSitemap({
        origin: "https://github.com/TheHalfMoon/kaf",
        sources: [{ pathname: "/docs/getting-started", lastModified: new Date("invalid") }],
      }),
    ).toEqual([{ url: "https://github.com/TheHalfMoon/kaf/docs/getting-started" }]);
  });
});
