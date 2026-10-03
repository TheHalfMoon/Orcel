import { afterEach, describe, expect, it, vi } from "vitest";
import { parseOrcelTargetInfo, readOrcelTargetInfo } from "./orcel-target.js";

describe("orcel target information", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("reads deployed runtime information", () => {
    expect(
      parseOrcelTargetInfo({
        agent: { name: "weather-agent", model: { id: "anthropic/claude-sonnet-5" } },
      }),
    ).toEqual({ name: "weather-agent", modelId: "anthropic/claude-sonnet-5" });
  });

  it("explains Vercel Deployment Protection redirects", async () => {
    const fetch = async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://vercel.com/sso-api?url=protected" },
      });

    await expect(
      readOrcelTargetInfo({
        cwd: "/workspace",
        orcelBin: "/orcel",
        target: "https://agent.example.com",
        fetch,
      }),
    ).rejects.toThrow("Vercel Deployment Protection requires authentication");
  });

  it("sends configured Vercel authentication headers", async () => {
    vi.stubEnv("VERCEL_AUTOMATION_BYPASS_SECRET", "bypass-secret");
    const fetch = vi.fn(async () =>
      Response.json({
        agent: { name: "weather-agent", model: { id: "anthropic/claude-sonnet-5" } },
      }),
    );

    await readOrcelTargetInfo({
      cwd: "/workspace",
      orcelBin: "/orcel",
      fetch,
      headers: { authorization: "Bearer oidc-token" },
      target: "https://agent.example.com",
    });

    expect(fetch).toHaveBeenCalledWith(
      "https://agent.example.com/orcel/v1/info",
      expect.objectContaining({
        headers: {
          authorization: "Bearer oidc-token",
          "x-vercel-protection-bypass": "bypass-secret",
        },
        redirect: "manual",
      }),
    );
  });

  it("reads local CLI information", () => {
    expect(
      parseOrcelTargetInfo({
        appRoot: "/workspace/weather-agent",
        model: "anthropic/claude-sonnet-5",
      }),
    ).toEqual({ name: "weather-agent", modelId: "anthropic/claude-sonnet-5" });
  });
});
