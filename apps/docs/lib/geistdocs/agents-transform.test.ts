import { describe, expect, it } from "vitest";
import { transformAgentsMarkdown } from "./agents-transform";

const input = `# kaf

## Documentation Surfaces

- Page-level Markdown: append .md or .mdx to a documentation URL

- [Full documentation context](https://github.com/TheHalfMoon/kaf/llms.txt): All configured documentation as Markdown

- To create an agent, get it as Markdown from /llms.mdx/getting-started (or via /llms.txt).
`;

describe("transformAgentsMarkdown", () => {
  it("describes canonical HTML and route-specific Markdown accurately", () => {
    const output = transformAgentsMarkdown(input, { origin: "https://github.com/TheHalfMoon/kaf", templates: [] });

    expect(output).toContain(
      "Canonical HTML pages use `/docs/...`, `/integrations/...`, and `/templates/...`",
    );
    expect(output).toContain("Docs and integration pages expose alternate Markdown");
    expect(output).toContain("Template pages are HTML discovery pages");
    expect(output).toContain("/docs/getting-started.md (or via /llms.txt)");
    expect(output).not.toContain("/llms.mdx/getting-started");
    expect(output).not.toContain("append .md or .mdx to a documentation URL");
    expect(output).toContain(
      "[Documentation index](https://github.com/TheHalfMoon/kaf/llms.txt): Curated task-oriented map",
    );
    expect(output).toContain(
      "[Full documentation context](https://github.com/TheHalfMoon/kaf/llms-full.txt): All configured documentation",
    );
    expect(output).not.toContain(
      "[Full documentation context](https://github.com/TheHalfMoon/kaf/llms.txt): All configured documentation",
    );
  });

  it("adds concise canonical template discovery entries", () => {
    const output = transformAgentsMarkdown(input, {
      origin: "https://github.com/TheHalfMoon/kaf",
      templates: [
        { slug: "chat", title: "Chat agent template", description: "A persisted chat agent." },
      ],
    });

    expect(output).toContain(
      "- [Chat agent template](https://github.com/TheHalfMoon/kaf/templates/chat): A persisted chat agent.",
    );
  });

  it("fails loudly if the upstream generic guidance changes", () => {
    expect(() =>
      transformAgentsMarkdown("# kaf", { origin: "https://github.com/TheHalfMoon/kaf", templates: [] }),
    ).toThrow("Geistdocs agents.md Markdown guidance changed");
  });
});
