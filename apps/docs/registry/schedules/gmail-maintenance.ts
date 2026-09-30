import { defineSchedule } from "kaf/schedules";

import { gmail } from "../channels/gmail";

export default defineSchedule({
  cron: "0 9 * * *",
  async run() {
    await gmail.watch();
  },
});
