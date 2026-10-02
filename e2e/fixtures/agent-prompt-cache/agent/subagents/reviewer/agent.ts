import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";

export default defineAgent({
  ...e2eSubagentConfig(),
  description:
    "Review one purchasing sheet. The review_sheet tool provides the sheet and its review question; the assignment only needs a sheet number.",
  reasoning: "low",
});
