import { e2eJudgeModel } from "@kaf-e2e/config";
import { defineEvalConfig } from "kaf/evals";

/** Resource shared by setup, evals, and teardown. */
export class SetupResource {
  #closed = false;

  read() {
    if (this.#closed) throw new Error("Eval setup resource is closed.");
    return "ready";
  }

  close() {
    this.#closed = true;
  }
}

export default defineEvalConfig({
  judge: { model: e2eJudgeModel() },
  setup() {
    return { resource: new SetupResource() };
  },
  teardown(context) {
    context?.resource.close();
  },
});
