import { describe, expect, it } from "vitest";
import {
  formatPageTitle,
  metadataTitle,
  pageTitleMetadata,
  rootTitleMetadata,
  siteTitle,
} from "./metadata-title";

describe("metadata titles", () => {
  it("defines normal child title inheritance at the shared layout", () => {
    expect(rootTitleMetadata).toEqual({
      default: "orcel – durable AI agent framework",
      template: "%s – orcel",
    });
    expect(metadataTitle("Integrations")).toBe("Integrations");
    expect(formatPageTitle("Integrations")).toBe("Integrations – orcel");
  });

  it("keeps the homepage title absolute", () => {
    expect(metadataTitle(siteTitle)).toEqual({ absolute: siteTitle });
    expect(pageTitleMetadata(siteTitle)).toEqual({
      title: { absolute: siteTitle },
      openGraph: { title: siteTitle },
      twitter: { title: siteTitle },
    });
  });

  it.each(["Self-host orcel", "Get started with orcel: durable AI agents in TypeScript"])(
    "does not suffix explicit standalone branding in %s",
    (title) => {
      expect(metadataTitle(title)).toEqual({ absolute: title });
      expect(formatPageTitle(title)).toBe(title);
    },
  );

  it("does not treat useOrcelAgent as standalone branding", () => {
    const title = "Build an AI agent chat UI with useOrcelAgent";
    expect(metadataTitle(title)).toBe(title);
    expect(formatPageTitle(title)).toBe(`${title} – orcel`);
  });

  it("applies the shared suffix to template titles", () => {
    expect(formatPageTitle("Chat template")).toBe("Chat template – orcel");
  });
});
