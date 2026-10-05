import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

export const ORCEL_ROUTE_PORTABILITY_DESCRIPTOR: ScenarioAppDescriptor = {
  files: {
    "agent/channels/orcel.ts": `import { none } from "@orcel/orcel/channels/auth";
import { orcelChannel } from "@orcel/orcel/channels/orcel";

export default orcelChannel({
  auth: none(),
});
`,
  },
  name: "orcel-route-portability",
};
