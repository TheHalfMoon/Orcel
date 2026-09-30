import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

export const KAF_ROUTE_PORTABILITY_DESCRIPTOR: ScenarioAppDescriptor = {
  files: {
    "agent/channels/kaf.ts": `import { none } from "kaf/channels/auth";
import { kafChannel } from "kaf/channels/kaf";

export default kafChannel({
  auth: none(),
});
`,
  },
  name: "kaf-route-portability",
};
