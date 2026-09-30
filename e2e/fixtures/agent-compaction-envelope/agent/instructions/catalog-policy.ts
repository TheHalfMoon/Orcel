import type { HookEvent } from "kaf/hooks";
import { defineDynamic, defineInstructions } from "kaf/instructions";

export default defineDynamic({
  events: {
    "turn.started": (event) => {
      // The preamble cannot read this turn's message yet; six seed turns precede expansion.
      if ((event as HookEvent<"turn.started">).data.sequence < 6) return null;
      return defineInstructions({
        role: "system",
        content: `EXPANDED_POLICY ${"Use the configured catalog policy. ".repeat(140)}`,
      });
    },
  },
});
