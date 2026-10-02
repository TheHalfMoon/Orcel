import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

export const ORCEL_ROUTE_PORTABILITY_DESCRIPTOR: ScenarioAppDescriptor = {
  files: {
    "agent/channels/orcel.ts": `import { none } from "orcel/channels/auth";
import { orcelChannel } from "orcel/channels/orcel";

export default orcelChannel({
  auth: none(),
});
`,
  },
  name: "orcel-route-portability",
};
