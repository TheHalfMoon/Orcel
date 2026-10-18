#!/usr/bin/env node
// BM-01: validates orcel-benchmark-report/1 files against
// docs/orcel/implementation-readiness/protocol/BENCHMARK_REPORT_1.schema.json.
//
// Usage: node scripts/check-benchmark-report.mjs [dir-or-file ...]
// Every *.report.json under each directory is checked. With no arguments the
// bundled samples directory is checked. Exits 1 on any violation.
//
// Dependency-free: implements only the JSON Schema keywords the schema uses
// and refuses a schema that uses any other keyword, so nothing is silently
// skipped.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const protocolDir = join(repoRoot, "docs/orcel/implementation-readiness/protocol");
export const schemaPath = join(protocolDir, "BENCHMARK_REPORT_1.schema.json");
export const samplesDir = join(protocolDir, "samples");

const annotationKeywords = new Set(["$schema", "$id", "$defs", "title", "description"]);
const validationKeywords = new Set([
  "type",
  "const",
  "enum",
  "pattern",
  "minLength",
  "maxLength",
  "minimum",
  "required",
  "properties",
  "additionalProperties",
  "items",
  "minItems",
  "$ref"
]);

export const loadSchema = (path = schemaPath) => {
  const schema = JSON.parse(readFileSync(path, "utf8"));
  assertSupported(schema, "#");
  return schema;
};

const assertSupported = (node, at) => {
  for (const [key, value] of Object.entries(node)) {
    if (!annotationKeywords.has(key) && !validationKeywords.has(key)) {
      throw new Error(`schema keyword ${key} at ${at} is not supported by this checker`);
    }
    if (key === "additionalProperties" && value !== false) {
      throw new Error(`schema at ${at}: only additionalProperties: false is supported`);
    }
  }
  for (const [name, sub] of Object.entries(node.properties ?? {})) assertSupported(sub, `${at}/properties/${name}`);
  for (const [name, sub] of Object.entries(node.$defs ?? {})) assertSupported(sub, `${at}/$defs/${name}`);
  if (node.items) assertSupported(node.items, `${at}/items`);
};

const resolveRef = (root, ref) => {
  if (!ref.startsWith("#/")) throw new Error(`unsupported $ref ${ref}`);
  let node = root;
  for (const part of ref.slice(2).split("/")) {
    node = node?.[part];
  }
  if (!node) throw new Error(`unresolved $ref ${ref}`);
  return node;
};

const typeOf = (value) => {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
};

const typeMatches = (expected, actual) => expected === actual || (expected === "number" && actual === "integer");

const pointer = (path) => (path.length === 0 ? "(root)" : "/" + path.join("/"));

const validateNode = (root, node, value, path, errors) => {
  if (node.$ref) {
    validateNode(root, resolveRef(root, node.$ref), value, path, errors);
  }
  const at = pointer(path);
  const actual = typeOf(value);
  if (node.type && !typeMatches(node.type, actual)) {
    errors.push(`${at}: expected ${node.type}, got ${actual}`);
    return;
  }
  if ("const" in node && value !== node.const) {
    errors.push(`${at}: must equal ${JSON.stringify(node.const)}`);
  }
  if (node.enum && !node.enum.includes(value)) {
    errors.push(`${at}: ${JSON.stringify(value)} is not one of ${node.enum.join(", ")}`);
  }
  if (actual === "string") {
    if (node.minLength !== undefined && [...value].length < node.minLength) {
      errors.push(`${at}: shorter than ${node.minLength} characters`);
    }
    if (node.maxLength !== undefined && [...value].length > node.maxLength) {
      errors.push(`${at}: longer than ${node.maxLength} characters`);
    }
    if (node.pattern && !new RegExp(node.pattern, "u").test(value)) {
      errors.push(`${at}: does not match ${node.pattern}`);
    }
  }
  if ((actual === "integer" || actual === "number") && node.minimum !== undefined && value < node.minimum) {
    errors.push(`${at}: below minimum ${node.minimum}`);
  }
  if (actual === "array") {
    if (node.minItems !== undefined && value.length < node.minItems) {
      errors.push(`${at}: fewer than ${node.minItems} items`);
    }
    if (node.items) {
      value.forEach((item, index) => validateNode(root, node.items, item, [...path, String(index)], errors));
    }
  }
  if (actual === "object") {
    for (const name of node.required ?? []) {
      if (!Object.hasOwn(value, name)) errors.push(`${at}: missing required property ${name}`);
    }
    const properties = node.properties ?? {};
    for (const [name, child] of Object.entries(value)) {
      if (Object.hasOwn(properties, name)) {
        validateNode(root, properties[name], child, [...path, name], errors);
      } else if (node.additionalProperties === false) {
        errors.push(`${at}: unexpected property ${name}`);
      }
    }
  }
};

export const validateReport = (report, schema = loadSchema()) => {
  const errors = [];
  validateNode(schema, schema, report, [], errors);
  return errors;
};

export const findReports = (target) => {
  const stats = statSync(target);
  if (stats.isFile()) return [target];
  const found = [];
  for (const entry of readdirSync(target, { withFileTypes: true })) {
    const full = join(target, entry.name);
    if (entry.isDirectory()) found.push(...findReports(full));
    else if (entry.isFile() && entry.name.endsWith(".report.json")) found.push(full);
  }
  return found.sort();
};

export const checkTargets = (targets, schema = loadSchema()) => {
  const failures = [];
  let checked = 0;
  for (const target of targets) {
    let files;
    try {
      files = findReports(resolve(target));
    } catch (error) {
      failures.push(`${target}: ${error.code === "ENOENT" ? "no such file or directory" : error.message}`);
      continue;
    }
    for (const file of files) {
      checked += 1;
      const label = relative(process.cwd(), file) || file;
      let report;
      try {
        report = JSON.parse(readFileSync(file, "utf8"));
      } catch (error) {
        failures.push(`${label}: invalid JSON: ${error.message}`);
        continue;
      }
      for (const message of validateReport(report, schema)) failures.push(`${label}: ${message}`);
    }
  }
  return { checked, failures };
};

const main = () => {
  const targets = process.argv.slice(2);
  const { checked, failures } = checkTargets(targets.length > 0 ? targets : [samplesDir]);
  if (failures.length > 0) {
    for (const failure of failures) process.stderr.write(`${failure}\n`);
    process.stderr.write(`benchmark report check failed: ${failures.length} problem(s) in ${checked} report(s)\n`);
    process.exit(1);
  }
  process.stdout.write(`benchmark report check passed: ${checked} report(s)\n`);
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
