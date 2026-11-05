#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [baseArg, headArg, repository, jevDirectory] = process.argv.slice(2);
const report = {
  schema_version: "1",
  reviewer: "TypeSafe Jev via pinned devagrawal09/jev-review checkout",
  jev_pin: "31f89602797fb7bea007f8a480bf368bf564954e",
  base_sha: baseArg ?? null,
  head_sha: headArg ?? null,
  diff: baseArg && headArg ? `${baseArg}..${headArg}` : null,
  changed_files: [],
  hunk_judgments: [],
  findings: [],
  blocking_findings: [],
  coverage: { expected_hunks: 0, reviewed_hunks: 0, complete: false },
  status: "FAILED",
};
if (!/^[0-9a-f]{40}$/.test(baseArg ?? "") || !/^[0-9a-f]{40}$/.test(headArg ?? "")) throw new Error("full lowercase SHAs required");
if (!repository || !jevDirectory) throw new Error("repository and JEV_DIR are required");
const sdkPath = join(jevDirectory, "node_modules", "@typesafe-ai", "sdk", "dist", "index.mjs");
const { TypeSafeClient, choice, noul, score, VERSION: sdkVersion } = await import(pathToFileURL(sdkPath).href);
const client = new TypeSafeClient();
report.typesafe_sdk_version = sdkVersion;
const dimensions = {
  correctness: "incorrect runtime behavior",
  security: "a weakened security boundary, secret exposure, injection, or unsafe default",
  reliability: "a crash, race, resource leak, hang, or incomplete cleanup",
  compatibility: "a broken caller, persisted format, protocol, or public behavior",
  testGap: "important changed behavior without adequate targeted test evidence",
};
const mechanisms = {
  correctness: ["condition", "state", "dataFlow", "asyncControl", "other", "noIssue"],
  security: ["authorization", "injection", "exposure", "unsafeDefault", "other", "noIssue"],
  reliability: ["cleanup", "concurrency", "recovery", "crash", "other", "noIssue"],
  compatibility: ["api", "behavior", "dataFormat", "protocol", "other", "noIssue"],
  testGap: ["branch", "failure", "boundary", "integration", "other", "noIssue"],
};
const severityRubric = ["No meaningful impact or no supported issue", "Minor or narrowly limited impact", "Significant correctness, reliability, compatibility, or security impact", "Critical security, data-loss, or widespread outage impact"];


function git(args) {
  return execFileSync("git", ["--literal-pathspecs", "-C", repository, ...args], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
}

function splitHunks(patch) {
  const lines = patch.split("\n");
  const firstHunk = lines.findIndex((line) => line.startsWith("@@ "));
  if (firstHunk < 0) throw new Error("changed file has no unified-diff hunk");
  const header = lines.slice(0, firstHunk).join("\n");
  const hunks = [];
  let current = null;
  for (const line of lines.slice(firstHunk)) {
    if (line.startsWith("@@ ")) {
      if (current) hunks.push(current);
      current = [line];
    } else if (current) current.push(line);
  }
  if (current) hunks.push(current);
  return hunks.map((hunk) => ({
    patch: `${header}\n${hunk.join("\n")}`,
    startLine: Number(hunk[0].match(/@@ .*\+(\d+)/)?.[1] ?? 1),
  }));
}

const MAX_REVIEW_SLICE_LINES = 200;
const MAX_REVIEW_SLICE_CHARS = 10_000;
const REVIEW_SLICE_OVERLAP_LINES = 3;

function splitReviewSlices(hunk) {
  const lines = hunk.patch.split("\n");
  const hunkHeader = lines.findIndex((line) => line.startsWith("@@ "));
  if (hunkHeader < 0) throw new Error("review hunk has no unified-diff header");
  const prefix = lines.slice(0, hunkHeader + 1);
  const body = lines.slice(hunkHeader + 1);
  if (body.length === 0) return [{ patch: hunk.patch, startLine: hunk.startLine }];

  const prefixChars = prefix.join("\n").length + 1;
  const slices = [];
  let start = 0;
  while (start < body.length) {
    let end = start;
    let chars = prefixChars;
    while (end < body.length && end - start < MAX_REVIEW_SLICE_LINES) {
      const nextChars = body[end].length + 1;
      if (end > start && chars + nextChars > MAX_REVIEW_SLICE_CHARS) break;
      if (end === start && chars + nextChars > MAX_REVIEW_SLICE_CHARS) {
        throw new Error("single diff line exceeds Jev review slice character budget");
      }
      chars += nextChars;
      end += 1;
    }
    if (end === start) throw new Error("failed to advance Jev review slice");
    slices.push({
      patch: `${prefix.join("\n")}\n${body.slice(start, end).join("\n")}`,
      startLine: hunk.startLine,
    });
    if (end >= body.length) break;
    const reviewedLines = end - start;
    start = reviewedLines > REVIEW_SLICE_OVERLAP_LINES ? end - REVIEW_SLICE_OVERLAP_LINES : end;
  }
  return slices;
}

try {
  git(["cat-file", "-e", `${baseArg}^{commit}`]);
  git(["cat-file", "-e", `${headArg}^{commit}`]);
  const names = git(["diff", "--name-only", "-z", baseArg, headArg]).split("\0").filter(Boolean);
  if (names.length === 0) throw new Error("the exact PR diff contains no files");
  for (const path of names) {
    const selectedNames = git(["diff", "--name-only", "-z", baseArg, headArg, "--", path]).split("\0").filter(Boolean);
    if (selectedNames.length !== 1 || selectedNames[0] !== path) throw new Error(`literal path selection mismatch: ${path}`);
    const numstat = git(["diff", "--numstat", baseArg, headArg, "--", path]).trim();
    if (numstat.startsWith("-\t-\t")) throw new Error(`binary file cannot be reviewed: ${path}`);
    const patch = git(["diff", "--no-ext-diff", "--no-color", "--unified=3", baseArg, headArg, "--", path]);
    const hunks = splitHunks(patch);
    const fileResult = { path, hunks: hunks.length, reviewed_hunks: 0, review_slices: 0, reviewed_slices: 0 };
    report.changed_files.push(fileResult);
    report.coverage.expected_hunks += hunks.length;
    for (const [index, hunk] of hunks.entries()) {
      const slices = splitReviewSlices(hunk);
      fileResult.review_slices += slices.length;
      for (const [sliceIndex, slice] of slices.entries()) {
        const questions = Object.fromEntries(Object.entries(dimensions).map(([key, definition]) => [key, noul(
          `Do the changed lines directly support that this change introduces ${definition}? Require a concrete reachable failure or security path; ignore style, unsupported speculation, and correctly strengthened controls.`,
          { true: "Direct evidence of a concrete issue", false: "No direct evidence of this issue" },
        )]));
        const reviewUnit = { ...slice, id: "slice_1", parent_hunk: index + 1, slice: sliceIndex + 1, slices: slices.length };
        const screening = await client.systemOne({ state: { file: path, hunk: reviewUnit }, questions });
        fileResult.reviewed_slices += 1;
        report.hunk_judgments.push({
          file: path, hunk: index + 1, slice: sliceIndex + 1, slices: slices.length, line: slice.startLine,
          screening: Object.fromEntries(Object.keys(dimensions).map((dimension) => [dimension, {
            probability: screening.answers[dimension].noul,
            confidence: screening.answers[dimension].confidence,
          }])),
        });
        for (const dimension of Object.keys(dimensions)) {
          const screened = screening.answers[dimension];
          if (screened.noul < 0.7) continue;
          const located = await client.systemOne({
            state: { file: path, dimension, screeningProbability: screened.noul, candidateHunks: [reviewUnit] },
            questions: { evidence: choice("Does this candidate hunk provide direct evidence for the suspected concern?", { slice_1: "Direct evidence", noIssue: "No defect established" }) },
          });
          if (located.answers.evidence.choice === "noIssue" || located.answers.evidence.confidence < 0.55) continue;
          const classification = await client.systemOne({
            state: { file: path, dimension, selectedEvidence: reviewUnit },
            questions: {
              mechanism: choice("Which concrete mechanism is supported by the evidence?", Object.fromEntries(mechanisms[dimension].map((item) => [item, item]))),
              severity: score("Assuming the evidence establishes the concern, rate its production impact.", severityRubric),
            },
          });
          if (classification.answers.mechanism.choice === "noIssue") continue;
          const finding = {
            file: path, hunk: index + 1, slice: sliceIndex + 1, line: slice.startLine, dimension,
            mechanism: classification.answers.mechanism.choice,
            severity: classification.answers.severity.score,
            confidence: classification.answers.severity.confidence,
            action: classification.answers.severity.score >= 2 ? "request_changes" : "comment",
            evidence: slice.patch,
          };
          report.findings.push(finding);
          if (finding.action === "request_changes") report.blocking_findings.push(finding);
        }
      }
      fileResult.reviewed_hunks += 1;
      report.coverage.reviewed_hunks += 1;
    }
  }
  report.coverage.complete = report.coverage.expected_hunks === report.coverage.reviewed_hunks && report.changed_files.every((file) => file.hunks === file.reviewed_hunks);
  if (!report.coverage.complete) throw new Error("not every exact-diff hunk received a Jev judgment");
  report.status = report.blocking_findings.length === 0 ? "PASSED" : "FAILED";
} catch (error) {
  // This goes into a public artifact, which GitHub's log masking doesn't reach.
  const message = error instanceof Error ? error.message : String(error);
  const key = process.env.TYPESAFE_API_KEY;
  report.error = key ? message.split(key).join("***") : message;
}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (report.status !== "PASSED") process.exitCode = 1;