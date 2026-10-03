import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description:
    "Researches product metrics, such as churn by region and quarter, in the team's research archive.",
  ...e2eSubagentConfig(),
});
