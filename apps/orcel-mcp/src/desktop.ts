import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { KernelClient } from "./kernel.js";
import { projectKernelResult } from "./result.js";

/**
 * SG-000095 local desktop surface.
 *
 * Read-only window listing/tree observation remains available without a Full
 * User grant. Every capture or actuation shape below is local-only at the MCP
 * contract, requires a valid Full User lease in orceld immediately before
 * dispatch, and retains the existing per-action approval and typed freshness
 * checks. MCP exposes no grant, renew, revoke, admin, or remote-full-control
 * operation.
 */
const MAX_TREE_DEPTH = 8;
const MAX_TREE_NODES = 256;
const MAX_VALUE_CHARS = 1024;
const MAX_TEXT_BYTES = 4096;
const MAX_KEY_BYTES = 64;
const MAX_SCROLL_TICKS = 20;
const WINDOW_ID = /^uia-win-[0-9a-f]{16}$/;
const ELEMENT_ID = /^uia-el-[0-9a-f]{16}$/;

const workspace = (defaultWorkspace: string) =>
  z.string().min(1).default(defaultWorkspace);
const generation = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const coordinate = z.number().int().min(0).max(1_000_000);
const signedScroll = z.number().int().min(-MAX_SCROLL_TICKS).max(MAX_SCROLL_TICKS);

export const DESKTOP_KERNEL_SHAPES = [
  ["uia.window", "list"],
  ["uia.tree", "observe"],
  ["desktop.cursor", "get"],
  ["uia.screenshot", "capture"],
  ["uia.element", "invoke"],
  ["uia.element", "set_value"],
  ["uia.element", "select"],
  ["uia.element", "toggle"],
  ["uia.element", "scroll"],
  ["desktop.input", "execute"],
  ["desktop.window", "action"]
] as const;

export function desktopWindowListSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace)
  });
}

export function desktopWindowTreeSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    window_id: z.string().regex(WINDOW_ID),
    window_generation: generation,
    max_depth: z.number().int().min(0).max(MAX_TREE_DEPTH).default(MAX_TREE_DEPTH),
    max_nodes: z.number().int().min(1).max(MAX_TREE_NODES).default(MAX_TREE_NODES),
    // SG-000128: an optional subtree root, an element id Orcel issued for this
    // window in its latest tree (tree_generation). Both or neither; orceld
    // validates the root again and applies the same caps below it.
    root_element_id: z.string().regex(ELEMENT_ID).optional(),
    tree_generation: generation.optional()
  }).refine(
    (value) => (value.root_element_id === undefined) === (value.tree_generation === undefined),
    "root_element_id and tree_generation go together"
  );
}

export function desktopCursorGetSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace)
  });
}

export function desktopWindowCaptureSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    window_id: z.string().regex(WINDOW_ID),
    window_generation: generation
  });
}

function elementBase(defaultWorkspace: string) {
  return {
    workspace_id: workspace(defaultWorkspace),
    element_id: z.string().regex(ELEMENT_ID),
    tree_generation: generation,
    control_type: z.string().min(1).max(256)
  };
}

export function desktopElementInvokeSchema(defaultWorkspace: string) {
  return z.object(elementBase(defaultWorkspace));
}

export function desktopElementSetValueSchema(defaultWorkspace: string) {
  return z.object({
    ...elementBase(defaultWorkspace),
    value: z.string().max(MAX_VALUE_CHARS).refine((value) => !value.includes("\0"), "value must not contain NUL")
  });
}

export function desktopElementSelectSchema(defaultWorkspace: string) {
  return z.object({
    ...elementBase(defaultWorkspace),
    expected_selected: z.boolean(),
    selected: z.boolean()
  });
}

export function desktopElementToggleSchema(defaultWorkspace: string) {
  return z.object({
    ...elementBase(defaultWorkspace),
    expected_toggled: z.boolean(),
    toggled: z.boolean()
  });
}

export function desktopElementScrollSchema(defaultWorkspace: string) {
  return z.object({
    ...elementBase(defaultWorkspace),
    direction: z.enum(["up", "down", "left", "right"]),
    amount: z.number().int().min(1).max(MAX_SCROLL_TICKS),
    expected_horizontal_percent: z.number().int().min(0).max(100),
    expected_vertical_percent: z.number().int().min(0).max(100)
  });
}

const windowInputBase = (defaultWorkspace: string) => ({
  workspace_id: workspace(defaultWorkspace),
  window_id: z.string().regex(WINDOW_ID),
  window_generation: generation
});

export function desktopInputExecuteSchema(defaultWorkspace: string) {
  const base = windowInputBase(defaultWorkspace);
  return z.discriminatedUnion("action", [
    z.object({ ...base, action: z.literal("move"), x: coordinate, y: coordinate }),
    z.object({ ...base, action: z.literal("click"), x: coordinate, y: coordinate }),
    z.object({ ...base, action: z.literal("double_click"), x: coordinate, y: coordinate }),
    z.object({ ...base, action: z.literal("right_click"), x: coordinate, y: coordinate }),
    z.object({
      ...base,
      action: z.literal("drag"),
      x: coordinate,
      y: coordinate,
      to_x: coordinate,
      to_y: coordinate
    }),
    z.object({
      ...base,
      action: z.literal("scroll"),
      x: coordinate,
      y: coordinate,
      scroll_x: signedScroll,
      scroll_y: signedScroll
    }).refine((value) => value.scroll_x !== 0 || value.scroll_y !== 0, "scroll must be non-zero"),
    z.object({
      ...base,
      action: z.literal("type_text"),
      text: z.string().min(1).refine(
        (value) => Buffer.byteLength(value, "utf8") <= MAX_TEXT_BYTES && !value.includes("\0"),
        "text must be at most 4096 UTF-8 bytes and contain no NUL"
      )
    }),
    z.object({
      ...base,
      action: z.literal("key"),
      key: z.string().min(1).refine((value) => Buffer.byteLength(value, "utf8") <= MAX_KEY_BYTES, "key is too long")
    }),
    z.object({
      ...base,
      action: z.literal("hotkey"),
      key: z.string().min(1).refine((value) => Buffer.byteLength(value, "utf8") <= MAX_KEY_BYTES, "hotkey is too long")
    })
  ]);
}

export function desktopWindowActionSchema(defaultWorkspace: string) {
  return z.object({
    ...windowInputBase(defaultWorkspace),
    action: z.enum(["focus", "minimize", "maximize", "restore", "close"])
  });
}

function elementArguments(input: {
  element_id: string;
  tree_generation: number;
  control_type: string;
}): Record<string, unknown> {
  return {
    element_id: input.element_id,
    expected_tree_generation: input.tree_generation,
    expected_control_type: input.control_type
  };
}

export function registerDesktopTools(
  server: McpServer,
  kernel: KernelClient,
  defaultWorkspace: string
): void {
  server.registerTool(
    "desktop_window_list",
    {
      description:
        "List visible top-level windows of other applications in the current interactive Windows session (at most 64), with typed window and process identities. Protected Orcel/Orcel surfaces are omitted. Read-only; no Full User grant is required.",
      inputSchema: desktopWindowListSchema(defaultWorkspace)
    },
    async ({ workspace_id }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.window",
          operation: "list",
          arguments: {}
        })
      )
  );

  server.registerTool(
    "desktop_window_tree",
    {
      description:
        "Read the bounded UI Automation control tree (depth at most 8, at most 256 elements) of one listed window, bound to its window_generation. Optionally read below one element of that window's latest tree instead (root_element_id with its tree_generation), with the same bounds; a few such reads per window until it changes or an approved action succeeds. Password values are never read. Read-only; no Full User grant is required.",
      inputSchema: desktopWindowTreeSchema(defaultWorkspace)
    },
    async ({ workspace_id, window_id, window_generation, max_depth, max_nodes, root_element_id, tree_generation }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.tree",
          operation: "observe",
          arguments: {
            window_id,
            expected_window_generation: window_generation,
            max_depth,
            max_nodes,
            ...(root_element_id === undefined
              ? {}
              : { root_element_id, expected_tree_generation: tree_generation })
          }
        })
      )
  );

  server.registerTool(
    "desktop_cursor_get",
    {
      description:
        "Read the current cursor position and interactive-screen geometry. Local Full User desktop authority must already be active; this tool cannot grant or renew it.",
      inputSchema: desktopCursorGetSchema(defaultWorkspace)
    },
    async ({ workspace_id }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "desktop.cursor",
          operation: "get",
          arguments: {}
        })
      )
  );

  server.registerTool(
    "desktop_window_capture",
    {
      description:
        "Capture exactly one typed target window under Full User authority. The call is SOFT-approved, exact-generation bound, excludes protected surfaces, and never widens to a monitor or whole desktop.",
      inputSchema: desktopWindowCaptureSchema(defaultWorkspace)
    },
    async ({ workspace_id, window_id, window_generation }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.screenshot",
          operation: "capture",
          arguments: {
            window_id,
            expected_window_generation: window_generation,
            scope: "target-window"
          }
        })
      )
  );

  server.registerTool(
    "desktop_element_invoke",
    {
      description:
        "Invoke one eligible UI Automation element under an active Full User lease and SOFT approval. Semantic UIA actuation is preferred over raw mouse/keyboard input.",
      inputSchema: desktopElementInvokeSchema(defaultWorkspace)
    },
    async ({ workspace_id, ...input }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.element",
          operation: "invoke",
          arguments: elementArguments(input)
        })
      )
  );

  server.registerTool(
    "desktop_element_set_value",
    {
      description:
        "Set one eligible non-password UI Automation value under an active Full User lease and SOFT approval. The exact element generation and value digest are approval-bound.",
      inputSchema: desktopElementSetValueSchema(defaultWorkspace)
    },
    async ({ workspace_id, value, ...input }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.element",
          operation: "set_value",
          arguments: { ...elementArguments(input), value }
        })
      )
  );

  server.registerTool(
    "desktop_element_select",
    {
      description:
        "Change one eligible UI Automation selection under an active Full User lease and SOFT approval, with exact prior-state and tree-generation binding.",
      inputSchema: desktopElementSelectSchema(defaultWorkspace)
    },
    async ({ workspace_id, expected_selected, selected, ...input }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.element",
          operation: "select",
          arguments: { ...elementArguments(input), expected_selected, selected }
        })
      )
  );

  server.registerTool(
    "desktop_element_toggle",
    {
      description:
        "Toggle one eligible UI Automation control under an active Full User lease and SOFT approval, with exact prior-state and tree-generation binding.",
      inputSchema: desktopElementToggleSchema(defaultWorkspace)
    },
    async ({ workspace_id, expected_toggled, toggled, ...input }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.element",
          operation: "toggle",
          arguments: { ...elementArguments(input), expected_toggled, toggled }
        })
      )
  );

  server.registerTool(
    "desktop_element_scroll",
    {
      description:
        "Scroll one eligible UI Automation element by at most 20 bounded ticks under an active Full User lease and SOFT approval. No wheel fallback is used by this semantic tool.",
      inputSchema: desktopElementScrollSchema(defaultWorkspace)
    },
    async ({
      workspace_id,
      direction,
      amount,
      expected_horizontal_percent,
      expected_vertical_percent,
      ...input
    }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "uia.element",
          operation: "scroll",
          arguments: {
            ...elementArguments(input),
            direction,
            amount,
            expected_horizontal_percent,
            expected_vertical_percent
          }
        })
      )
  );

  server.registerTool(
    "desktop_input_execute",
    {
      description:
        "Execute one bounded real mouse/keyboard action against an exact typed window under an active Full User lease and SOFT approval. Prefer semantic desktop_element_* tools when possible. Human-input drift cancels before dispatch and uncertain post-dispatch outcomes are never retried automatically.",
      inputSchema: desktopInputExecuteSchema(defaultWorkspace)
    },
    async (input) => {
      const { workspace_id, window_id, window_generation, ...action } = input;
      return projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "desktop.input",
          operation: "execute",
          arguments: {
            window_id,
            expected_window_generation: window_generation,
            ...action
          }
        })
      );
    }
  );

  server.registerTool(
    "desktop_window_action",
    {
      description:
        "Focus, minimize, maximize, restore, or close one exact typed window under an active Full User lease and SOFT approval. Protected/security surfaces and stale identities fail closed.",
      inputSchema: desktopWindowActionSchema(defaultWorkspace)
    },
    async ({ workspace_id, window_id, window_generation, action }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "desktop.window",
          operation: "action",
          arguments: {
            window_id,
            expected_window_generation: window_generation,
            action
          }
        })
      )
  );
}
