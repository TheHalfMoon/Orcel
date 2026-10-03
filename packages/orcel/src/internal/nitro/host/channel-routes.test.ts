import { describe, expect, it } from "vitest";

import { createDevelopmentNitroArtifactsConfig } from "#internal/nitro/host/artifacts-config.js";
import { registerChannelVirtualHandlers } from "#internal/nitro/host/channel-routes.js";

describe("registerChannelVirtualHandlers", () => {
  it("wraps CORS-enabled HTTP routes and registers preflight handlers", () => {
    const nitro = {
      options: {
        handlers: [] as any[],
        virtual: {} as Record<string, string>,
      },
    };

    registerChannelVirtualHandlers(nitro, {
      artifactsConfig: createDevelopmentNitroArtifactsConfig({
        appRoot: "/app",
      }),
      routes: [
        { cors: {}, kind: "channel", method: "POST", path: "/orcel/v1/session" },
        {
          cors: {},
          kind: "channel-preflight",
          method: "OPTIONS",
          path: "/orcel/v1/session",
        },
      ],
    });

    expect(nitro.options.handlers).toEqual([
      {
        handler: "#nitro/virtual/orcel-channel/POST /orcel/v1/session",
        method: "POST",
        route: "/orcel/v1/session",
      },
      {
        handler: "#nitro/virtual/orcel-channel/OPTIONS /orcel/v1/session",
        method: "OPTIONS",
        route: "/orcel/v1/session",
      },
    ]);
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/POST /orcel/v1/session"]).toContain(
      "handleCors",
    );
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/POST /orcel/v1/session"]).toContain(
      "dispatchChannelRequest",
    );
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/OPTIONS /orcel/v1/session"]).toContain(
      "return new Response(null, { status: 204 });",
    );
  });

  it("registers one preflight handler per CORS-enabled path", () => {
    const nitro = {
      options: {
        handlers: [] as any[],
        virtual: {} as Record<string, string>,
      },
    };

    registerChannelVirtualHandlers(nitro, {
      artifactsConfig: createDevelopmentNitroArtifactsConfig({
        appRoot: "/app",
      }),
      routes: [
        {
          cors: {},
          kind: "channel",
          method: "GET",
          path: "/orcel/v1/session/:sessionId/events",
        },
        {
          cors: {},
          kind: "channel-preflight",
          method: "OPTIONS",
          path: "/orcel/v1/session/:sessionId/events",
        },
        {
          cors: {},
          kind: "channel",
          method: "POST",
          path: "/orcel/v1/session/:sessionId/events",
        },
      ],
    });

    expect(
      nitro.options.handlers.filter(
        (handler) =>
          handler.method === "OPTIONS" && handler.route === "/orcel/v1/session/:sessionId/events",
      ),
    ).toHaveLength(1);
  });

  it("registers websocket routes with the websocket dispatcher", () => {
    const nitro = {
      options: {
        handlers: [] as any[],
        virtual: {} as Record<string, string>,
      },
    };

    registerChannelVirtualHandlers(nitro, {
      artifactsConfig: createDevelopmentNitroArtifactsConfig({
        appRoot: "/app",
      }),
      routes: [{ kind: "channel", method: "WEBSOCKET", path: "/voice" }],
    });

    expect(nitro.options.handlers).toEqual([
      {
        handler: "#nitro/virtual/orcel-channel/WEBSOCKET /voice",
        route: "/voice",
      },
    ]);
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/WEBSOCKET /voice"]).toContain(
      "defineWebSocketHandler",
    );
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/WEBSOCKET /voice"]).not.toContain(
      'from "nitro"',
    );
    expect(nitro.options.virtual["#nitro/virtual/orcel-channel/WEBSOCKET /voice"]).toContain(
      "dispatchChannelWebSocketRequest",
    );
  });
});
