import { teamsChannel } from "@orcel/orcel/channels/teams";

export default teamsChannel({
  credentials: {
    appId: () => process.env.TEAMS_APP_ID!,
    appPassword: () => process.env.TEAMS_APP_PASSWORD!,
  },
});
