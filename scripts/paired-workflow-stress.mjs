import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { collectWorkflowStressMetrics } from "./workflow-stress-report.mjs";
import {
  captureWorkflowStressRun,
  createPairedWorkflowReport,
  renderPairedWorkflowMarkdown,
} from "./paired-workflow-stress-lib.mjs";

function parseArgs(argv) {
  const [command, ...args] = argv;
  if (!["capture", "compare"].includes(command)) throw new Error("Expected capture or compare");
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    if (!args[index]?.startsWith("--") || !args[index + 1]) throw new Error("Invalid CLI argument");
    const name = args[index].slice(2);
    if (Object.hasOwn(options, name)) throw new Error("Duplicate argument " + name);
    options[name] = args[index + 1];
  }
  const expected =
    command === "capture"
      ? [
          "artifacts",
          "sha",
          "orcel-version",
          "workflow-core-version",
          "workflow-world-version",
          "workflow-host-world-version",
          "deployment-id",
          "run-id",
          "run-attempt",
          "report",
          "output",
        ]
      : ["base", "head", "summary", "markdown"];
  if (
    expected.some((key) => !options[key]) ||
    Object.keys(options).some((key) => !expected.includes(key))
  ) {
    throw new Error("Missing or unsupported " + command + " arguments: " + expected.join(", "));
  }
  return { command, options };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}
async function writeJson(path, value) {
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, JSON.stringify(value, null, 2) + "\n");
}

export async function main(argv) {
  const { command, options } = parseArgs(argv);
  if (command === "capture") {
    const originalReport = await readJson(options.report);
    if (
      originalReport?.metadata?.sha !== options.sha ||
      String(originalReport?.metadata?.runId) !== options["run-id"] ||
      String(originalReport?.metadata?.attempt) !== options["run-attempt"]
    ) {
      throw new Error("Hosted report provenance does not match requested SHA and run ID");
    }
    if (originalReport.metadata.model !== "mock") {
      throw new Error("Hosted stress artifact must come from the deterministic mock-model run");
    }
    if (originalReport.metadata.deploymentId !== options["deployment-id"]) {
      throw new Error("Hosted deployment ID disagrees with report provenance or is missing");
    }
    for (const [source, requested] of [
      ["orcelVersion", "orcel-version"],
      ["workflowCoreVersion", "workflow-core-version"],
      ["workflowWorldVersion", "workflow-world-version"],
      ["workflowHostWorldVersion", "workflow-host-world-version"],
    ]) {
      if (originalReport.metadata[source] !== options[requested]) {
        throw new Error("Hosted version disagrees with report provenance: " + source);
      }
    }
    const metrics = await collectWorkflowStressMetrics(options.artifacts);
    const identity = {
      sha: options.sha,
      orcelVersion: options["orcel-version"],
      workflowCoreVersion: options["workflow-core-version"],
      workflowWorldVersion: options["workflow-world-version"],
      workflowHostWorldVersion: options["workflow-host-world-version"],
      deploymentId: options["deployment-id"],
      runId: options["run-id"],
      runAttempt: options["run-attempt"],
      model: "mock",
    };
    const capture = captureWorkflowStressRun(metrics, identity);
    await writeJson(options.output, capture);
    return capture;
  }
  const base = await readJson(options.base);
  const head = await readJson(options.head);
  const summary = createPairedWorkflowReport(base, head);
  await writeJson(options.summary, summary);
  await mkdir(dirname(resolve(options.markdown)), { recursive: true });
  await writeFile(options.markdown, renderPairedWorkflowMarkdown(summary) + "\n");
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main(process.argv.slice(2));
}
