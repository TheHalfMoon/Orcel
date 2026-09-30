import { defineSchedule } from "#public/schedules/index.js";

// Epoch 19 run inputs could carry an `activityObserver`; kaf now ignores it.
export default defineSchedule({
  cron: "0 9 * * *",
  async run({ appAuth, waitUntil }) {
    waitUntil(Promise.resolve(appAuth.principalId));
  },
});
