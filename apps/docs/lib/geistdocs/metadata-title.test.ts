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
      default: "kaf – durable AI agent framework",
      template: "%s – kaf",
    });
    expect(metadataTitle("Integrations")).toBe("Integrations");
    expect(formatPageTitle("Integrations")).toBe("Integrations – kaf");
  });

  it("keeps the homepage title absolute", () => {
    expect(metadataTitle(siteTitle)).toEqual({ absolute: siteTitle });
    expect(pageTitleMetadata(siteTitle)).toEqual({
      title: { absolute: siteTitle },
      openGraph: { title: siteTitle },
      twitter: { title: siteTitle },
    });
  });

  it.each(["Self-host kaf", "Get started with kaf: durable AI agents in TypeScript"])(
    "does not suffix explicit standalone branding in %s",
    (title) => {
      expect(metadataTitle(title)).toEqual({ absolute: title });
      expect(formatPageTitle(title)).toBe(title);
    },
  );

  it("does not treat useKafAgent as standalone branding", () => {
    const title = "Build an AI agent chat UI with useKafAgent";
    expect(metadataTitle(title)).toBe(title);
    expect(formatPageTitle(title)).toBe(`${title} – kaf`);
  });

  it("applies the shared suffix to template titles", () => {
    expect(formatPageTitle("Chat template")).toBe("Chat template – kaf");
  });
});
