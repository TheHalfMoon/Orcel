import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

export const TELEGRAM_ROUTE_PORTABILITY_DESCRIPTOR: ScenarioAppDescriptor = {
  files: {
    "agent/channels/telegram.ts": `import { telegramChannel } from "kaf/channels/telegram";

export default telegramChannel();
`,
  },
  name: "telegram-route-portability",
};
