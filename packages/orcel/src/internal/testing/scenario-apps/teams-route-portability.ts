import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

export const TEAMS_ROUTE_PORTABILITY_DESCRIPTOR: ScenarioAppDescriptor = {
  files: {
    "agent/channels/teams.ts": `import { teamsChannel } from "orcel/channels/teams";

export default teamsChannel();
`,
  },
  name: "teams-route-portability",
};
