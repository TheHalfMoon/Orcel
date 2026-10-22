import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_TOOL_NAMES } from "./server.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");

interface Workflow {
  id: string;
  status: string;
  via?: string[];
}

interface Capability {
  capability: string;
  operation: string;
  status: string;
  mcp_tool?: string;
}

interface Inventory {
  schema: string;
  workflows: Workflow[];
  capabilities: Capability[];
}

interface ReferencedSource {
  repository: string;
  revision: string;
  license: string;
}

interface Donor {
  id: string;
  repository: string;
  revision: string;
  license: string;
  license_path: string;
  source_paths: string[];
  reuse: string;
  runtime_imported: boolean;
  referenced_sources?: ReferencedSource[];
  non_admissible_unpinned_sources?: string[];
}

interface ParityEntry {
  workflow: string;
  classification: string;
  reason: string;
}

interface DonorReuseEntry {
  id: string;
  donor_id: string;
  subsystem: string;
  source_revision: string;
  source_paths: string[];
  cotra_destinations: string[];
  classification: string;
  license_obligation: string;
  dependency_obligation: string;
  authority_delta: string;
  reason: string;
}

interface Replacement {
  donor_shape: string;
  workflow: string;
  expected_status: string;
}

interface UiTarsClassification {
  subsystem: string;
  workflow: string;
  expected_status: string;
  disposition: string;
}

interface LocalAuthorityDenial {
  capability: string;
  operation: string;
}

interface ExitEvidence {
  schema: string;
  grain: string;
  canonical_base: string;
  authority_delta: string;
  parity_categories: string[];
  donor_reuse_categories: string[];
  donors: Donor[];
  parity_matrix: ParityEntry[];
  donor_reuse_matrix: DonorReuseEntry[];
  desktop_commander_replacement: Replacement[];
  desktop_commander_denials: string[];
  ui_tars_classification: UiTarsClassification[];
  local_authority_denials: LocalAuthorityDenial[];
  qualification: {
    authoritative_mcp_builder: string;
    tool_contract: string;
    daemon_entrypoint: string;
    parity_inventory: string;
    tests: string[];
  };
  exit_invariants: string[];
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(join(repo, path), "utf8")) as T;
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort();
}

function collectFiles(root: string, predicate: (path: string) => boolean): string[] {
  const files: string[] = [];
  const visit = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) {
        visit(child);
      } else if (predicate(child)) {
        files.push(child);
      }
    }
  };
  visit(root);
  return files;
}

const evidence = readJson<ExitEvidence>("docs/p16/sg000066_exit_evidence.json");
const inventory = readJson<Inventory>("docs/p16/capability_parity_inventory.json");
const workflows = new Map(inventory.workflows.map((entry) => [entry.id, entry]));
const capabilities = new Map(
  inventory.capabilities.map((entry) => [`${entry.capability}/${entry.operation}`, entry])
);

const REQUIRED_PARITY_CATEGORIES = [
  "COTRA_NATIVE",
  "COTRA_SUPERIOR",
  "DONOR_ADAPTED",
  "SAFE_SUCCESSOR_REQUIRED",
  "INTENTIONALLY_DENIED"
];

const REQUIRED_DONOR_REUSE_CATEGORIES = [
  "REUSE_VERBATIM",
  "ADAPT",
  "PORT",
  "REFERENCE_ONLY",
  "REJECT_FOR_COTRA"
];

const REQUIRED_REPLACEMENT_WORKFLOWS = [
  "create_directory",
  "delete_file",
  "edit_block",
  "file_info",
  "list_directory",
  "list_processes",
  "move_or_rename",
  "read_file",
  "read_file_range",
  "read_multiple_files",
  "run_bounded_program",
  "run_build_and_test_tools",
  "search_file_content",
  "search_file_names",
  "write_file"
];

const REQUIRED_DESKTOP_COMMANDER_DENIALS = [
  "agent_changes_own_policy",
  "arbitrary_network_sockets",
  "background_long_running_processes",
  "browser_script_or_devtools",
  "elevation_or_admin",
  "install_software_or_services",
  "interactive_repl_sessions",
  "kill_arbitrary_process",
  "powershell_or_cmd",
  "read_outside_workspaces",
  "shell_command_string"
];

// SG-000108 exposed browser_structured as its governed successor.
const SUCCESSOR_OVERRIDDEN_WORKFLOWS = new Set(["desktop_act", "screenshots", "browser_structured"]);

const REQUIRED_UI_TARS_CLASSIFICATIONS: Record<string, { status: string; disposition: string }> = {
  browser_structured: { status: "missing", disposition: "defer_to_governed_successor" },
  desktop_act: { status: "missing", disposition: "defer_to_governed_successor" },
  screenshots: { status: "missing", disposition: "defer_to_governed_successor" },
  browser_script_or_devtools: { status: "intentionally_denied", disposition: "deny" },
  arbitrary_network_sockets: { status: "intentionally_denied", disposition: "deny" },
  agent_changes_own_policy: { status: "intentionally_denied", disposition: "deny" }
};

const REQUIRED_UI_TARS_REUSE_IDS = [
  "ui_tars_action_parser",
  "ui_tars_agent_loop",
  "ui_tars_browser_evaluate",
  "ui_tars_browser_mcp_and_puppeteer",
  "ui_tars_command_and_script_execution",
  "ui_tars_electron_ipc",
  "ui_tars_event_stream",
  "ui_tars_nutjs_operator",
  "ui_tars_operator_abstraction",
  "ui_tars_personal_browser_profile",
  "ui_tars_raw_model_to_input",
  "ui_tars_remote_computer_and_browser",
  "ui_tars_screenshot_and_dpi"
];

const REQUIRED_UI_TARS_REJECTED_IDS = [
  "ui_tars_browser_evaluate",
  "ui_tars_command_and_script_execution",
  "ui_tars_personal_browser_profile",
  "ui_tars_raw_model_to_input",
  "ui_tars_remote_computer_and_browser"
];

const REQUIRED_KERNUX_REFERENCED_SOURCES: Record<string, { revision: string; license: string }> = {
  "stablyai/orca": {
    revision: "0d23ea6e688410c878096dab8b1779857354b7d4",
    license: "MIT"
  },
  "tinyfish-io/agentql": {
    revision: "418ba8ad1c69dfac134a6833369a01dfba5a24a7",
    license: "MIT"
  },
  "wonderwhy-er/DesktopCommanderMCP": {
    revision: "08ff76192919a6e8fe2557b39c3f99e7b54c3b92",
    license: "MIT"
  },
  "opensymph/open-computer-use": {
    revision: "5b433b98019c18201a15d11e8c3cb0010879a3d8",
    license: "MIT"
  },
  "bytedance/UI-TARS-desktop": {
    revision: "2ff41a9e515828c5bd5b276e493d73aa0bdf4a3a",
    license: "Apache-2.0"
  }
};

const REQUIRED_LOCAL_AUTHORITY_DENIALS = [
  "executable.registry.add/add",
  "remote.enrollment.authorize/authorize",
  "remote.lease.create/create",
  "trust.revoke_emergency/revoke",
  "workspace.trust.grant/grant"
];

test("SG-000066 exit evidence is pinned and authority-neutral", () => {
  assert.equal(evidence.schema, "quntal-p16-exit-evidence/2");
  assert.equal(evidence.grain, "SG-000066");
  assert.match(evidence.canonical_base, /^[0-9a-f]{40}$/);
  assert.equal(evidence.canonical_base, "e770a6913d11c92d6855943f6e47d306a5c42fca");
  assert.equal(evidence.authority_delta, "none");
  assert.deepEqual(sorted(evidence.parity_categories), sorted(REQUIRED_PARITY_CATEGORIES));
  assert.deepEqual(sorted(evidence.donor_reuse_categories), sorted(REQUIRED_DONOR_REUSE_CATEGORIES));
  assert.ok(evidence.exit_invariants.length >= 7);
});

test("Desktop Commander, Kernux source pool, and UI-TARS donors are exact reference-only pins", () => {
  assert.deepEqual(sorted(evidence.donors.map((entry) => entry.id)), [
    "desktop_commander",
    "kernux_source_pool",
    "ui_tars"
  ]);

  const desktopCommander = evidence.donors.find((entry) => entry.id === "desktop_commander");
  assert.ok(desktopCommander);
  assert.equal(desktopCommander.repository, "wonderwhy-er/DesktopCommanderMCP");
  assert.equal(desktopCommander.revision, "c774c3b505de990219637ecdc9a830c8772fae9d");
  assert.equal(desktopCommander.license, "MIT");

  const kernux = evidence.donors.find((entry) => entry.id === "kernux_source_pool");
  assert.ok(kernux);
  assert.equal(kernux.repository, "TheHalfMoon/kernux");
  assert.equal(kernux.revision, "828e71a6464e055712e77c85d2fc94bfd8f96e3b");
  assert.equal(kernux.license, "Apache-2.0");
  assert.ok(kernux.non_admissible_unpinned_sources?.some((entry) => entry.includes("TinyFish")));

  const referencedSources = new Map(
    (kernux.referenced_sources ?? []).map((entry) => [entry.repository, entry])
  );
  assert.deepEqual(sorted(referencedSources.keys()), sorted(Object.keys(REQUIRED_KERNUX_REFERENCED_SOURCES)));
  for (const [repository, required] of Object.entries(REQUIRED_KERNUX_REFERENCED_SOURCES)) {
    const source = referencedSources.get(repository);
    assert.ok(source, repository);
    assert.equal(source.revision, required.revision, repository);
    assert.equal(source.license, required.license, repository);
  }

  const uiTars = evidence.donors.find((entry) => entry.id === "ui_tars");
  assert.ok(uiTars);
  assert.equal(uiTars.repository, "bytedance/UI-TARS-desktop");
  assert.equal(uiTars.revision, "2ff41a9e515828c5bd5b276e493d73aa0bdf4a3a");
  assert.equal(uiTars.license, "Apache-2.0");

  for (const donor of evidence.donors) {
    assert.match(donor.revision, /^[0-9a-f]{40}$/);
    assert.equal(donor.reuse, "REFERENCE_ONLY");
    assert.equal(donor.runtime_imported, false);
    assert.ok(donor.license_path.length > 0);
    assert.ok(donor.source_paths.length > 0);
  }
});

test("the parity matrix covers all 36 workflows exactly once using the SG-000066 vocabulary", () => {
  assert.equal(inventory.workflows.length, 36);
  const actualIds = evidence.parity_matrix.map((entry) => entry.workflow);
  assert.equal(new Set(actualIds).size, actualIds.length, "duplicate parity workflow");
  assert.deepEqual(sorted(actualIds), sorted(workflows.keys()));

  const categories = new Set(evidence.parity_categories);
  for (const entry of evidence.parity_matrix) {
    const workflow = workflows.get(entry.workflow);
    assert.ok(workflow, `unknown parity workflow ${entry.workflow}`);
    assert.ok(categories.has(entry.classification), `unknown parity classification ${entry.classification}`);
    assert.ok(entry.reason.trim().length > 0, `${entry.workflow} needs a stated reason`);

    if (SUCCESSOR_OVERRIDDEN_WORKFLOWS.has(entry.workflow)) {
      assert.equal(workflow.status, "implemented_exposed", entry.workflow);
      assert.equal(entry.classification, "SAFE_SUCCESSOR_REQUIRED", entry.workflow);
      assert.ok(workflow.via && workflow.via.length > 0, entry.workflow);
    } else if (workflow.status === "implemented_exposed") {
      assert.ok(
        ["COTRA_NATIVE", "COTRA_SUPERIOR", "DONOR_ADAPTED"].includes(entry.classification),
        `${entry.workflow} is exposed but classified ${entry.classification}`
      );
    } else if (workflow.status === "missing") {
      assert.equal(entry.classification, "SAFE_SUCCESSOR_REQUIRED", entry.workflow);
    } else if (workflow.status === "intentionally_denied") {
      assert.equal(entry.classification, "INTENTIONALLY_DENIED", entry.workflow);
    } else {
      assert.fail(`workflow ${entry.workflow} has unsupported matrix status ${workflow.status}`);
    }
  }
});

test("the donor reuse matrix is complete, pinned, obligation-bearing, and import-neutral", () => {
  const donorIds = new Set(evidence.donors.map((entry) => entry.id));
  const reuseCategories = new Set(evidence.donor_reuse_categories);
  const ids = evidence.donor_reuse_matrix.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate donor reuse row");

  for (const entry of evidence.donor_reuse_matrix) {
    assert.ok(donorIds.has(entry.donor_id), `${entry.id} names unknown donor ${entry.donor_id}`);
    assert.ok(reuseCategories.has(entry.classification), `${entry.id} has unknown reuse classification`);
    assert.ok(["REFERENCE_ONLY", "REJECT_FOR_COTRA"].includes(entry.classification), `${entry.id} would import donor source in SG-000066`);
    assert.match(entry.source_revision, /^[0-9a-f]{40}$/);
    assert.ok(entry.source_paths.length > 0, `${entry.id} needs exact source paths`);
    assert.ok(entry.subsystem.trim().length > 0);
    assert.ok(entry.license_obligation.trim().length > 0);
    assert.ok(entry.dependency_obligation.trim().length > 0);
    assert.ok(entry.authority_delta.trim().length > 0);
    assert.ok(entry.reason.trim().length > 0);
  }

  const uiTarsRows = evidence.donor_reuse_matrix.filter((entry) => entry.donor_id === "ui_tars");
  assert.deepEqual(sorted(uiTarsRows.map((entry) => entry.id)), REQUIRED_UI_TARS_REUSE_IDS);
  for (const entry of uiTarsRows) {
    assert.equal(entry.source_revision, "2ff41a9e515828c5bd5b276e493d73aa0bdf4a3a", entry.id);
  }
  for (const id of REQUIRED_UI_TARS_REJECTED_IDS) {
    const entry = uiTarsRows.find((candidate) => candidate.id === id);
    assert.ok(entry, id);
    assert.equal(entry.classification, "REJECT_FOR_COTRA", id);
    assert.equal(entry.cotra_destinations.length, 0, `${id} must have no Orcel destination`);
  }

  assert.deepEqual(
    sorted(evidence.donor_reuse_matrix.filter((entry) => entry.donor_id === "kernux_source_pool").map((entry) => entry.id)),
    ["kernux_computer_use_boundary_patterns", "kernux_provenance_and_import_controls"]
  );
});

test("the Desktop Commander replacement matrix cannot silently shrink or widen", () => {
  const actual = evidence.desktop_commander_replacement.map((entry) => entry.workflow);
  assert.deepEqual(sorted(actual), REQUIRED_REPLACEMENT_WORKFLOWS);
  assert.equal(new Set(actual).size, actual.length, "duplicate replacement workflow");

  for (const replacement of evidence.desktop_commander_replacement) {
    const workflow = workflows.get(replacement.workflow);
    assert.ok(workflow, `unknown replacement workflow ${replacement.workflow}`);
    assert.equal(workflow.status, replacement.expected_status, replacement.workflow);
    assert.equal(workflow.status, "implemented_exposed", replacement.workflow);
    assert.ok(workflow.via && workflow.via.length > 0, replacement.workflow);
    for (const tool of workflow.via ?? []) {
      assert.ok(CANONICAL_TOOL_NAMES.includes(tool), `${replacement.workflow} names non-canonical tool ${tool}`);
    }
  }
});

test("Desktop Commander high-authority shapes remain explicit denials", () => {
  assert.deepEqual(sorted(evidence.desktop_commander_denials), REQUIRED_DESKTOP_COMMANDER_DENIALS);
  for (const id of evidence.desktop_commander_denials) {
    const workflow = workflows.get(id);
    assert.ok(workflow, `unknown denial workflow ${id}`);
    assert.equal(workflow.status, "intentionally_denied", id);
    assert.equal(workflow.via, undefined, `${id} must not expose an MCP route`);
  }
});

test("UI-TARS authority is either deferred or denied, never imported by SG-000066", () => {
  const actual = new Map(evidence.ui_tars_classification.map((entry) => [entry.workflow, entry]));
  assert.deepEqual(sorted(actual.keys()), sorted(Object.keys(REQUIRED_UI_TARS_CLASSIFICATIONS)));

  for (const [workflowId, required] of Object.entries(REQUIRED_UI_TARS_CLASSIFICATIONS)) {
    const classification = actual.get(workflowId);
    assert.ok(classification, workflowId);
    assert.equal(classification.expected_status, required.status, workflowId);
    assert.equal(classification.disposition, required.disposition, workflowId);

    const workflow = workflows.get(workflowId);
    assert.ok(workflow, `unknown UI-TARS-classified workflow ${workflowId}`);
    if (SUCCESSOR_OVERRIDDEN_WORKFLOWS.has(workflowId)) {
      assert.equal(required.status, "missing", workflowId);
      assert.equal(required.disposition, "defer_to_governed_successor", workflowId);
      assert.equal(workflow.status, "implemented_exposed", workflowId);
      assert.ok(workflow.via && workflow.via.length > 0, workflowId);
    } else {
      assert.equal(workflow.status, required.status, workflowId);
      assert.equal(workflow.via, undefined, `${workflowId} must not expose an MCP route`);
    }
  }
});

test("local authority remains unavailable to agents", () => {
  const actual = evidence.local_authority_denials.map((entry) => `${entry.capability}/${entry.operation}`);
  assert.deepEqual(sorted(actual), REQUIRED_LOCAL_AUTHORITY_DENIALS);

  for (const key of actual) {
    const capability = capabilities.get(key);
    assert.ok(capability, `unknown local-authority shape ${key}`);
    assert.equal(capability.status, "intentionally_denied", key);
    assert.equal(capability.mcp_tool, undefined, `${key} must not have an MCP tool`);
  }
});

test("every qualification artifact in the exit manifest exists", () => {
  const paths = [
    evidence.qualification.authoritative_mcp_builder,
    evidence.qualification.tool_contract,
    evidence.qualification.daemon_entrypoint,
    evidence.qualification.parity_inventory,
    ...evidence.qualification.tests
  ];
  assert.equal(new Set(paths).size, paths.length, "duplicate qualification path");
  for (const historicalPath of paths) {
  const currentPath = historicalPath
    .replace(/^apps\/quntal-mcp\//, "apps/orcel-mcp/")
    .replace(/^crates\/quntald\//, "crates/orceld/");
  const absolute = join(repo, currentPath);
  assert.ok(existsSync(absolute), `missing current qualification artifact for historical ${historicalPath}: ${currentPath}`);
  assert.ok(statSync(absolute).isFile(), `qualification artifact is not a file ${currentPath}`);
}
});

test("SG-000066 imports no Desktop Commander, Kernux, or UI-TARS runtime", () => {
  const runtimeFiles = [
    join(repo, "package.json"),
    join(repo, "package-lock.json"),
    join(repo, "Cargo.toml"),
    join(repo, "Cargo.lock"),
    join(repo, "apps", "orcel-mcp", "package.json"),
    join(repo, "apps", "orcel-relay", "package.json"),
    ...collectFiles(join(repo, "apps", "orcel-mcp", "src"), (path) => path.endsWith(".ts") && !path.endsWith(".test.ts")),
    ...collectFiles(join(repo, "apps", "orcel-relay", "src"), (path) => path.endsWith(".ts") && !path.endsWith(".test.ts")),
    ...collectFiles(join(repo, "crates"), (path) => path.endsWith(".rs"))
  ];
  const forbiddenRuntimeMarkers = [
    "desktopcommandermcp",
    "@ui-tars",
    "ui-tars",
    "operator-browser",
    "thehalfmoon/kernux"
  ];

  for (const path of runtimeFiles) {
    const content = readFileSync(path, "utf8").toLowerCase();
    for (const marker of forbiddenRuntimeMarkers) {
      assert.equal(content.includes(marker), false, `${path} imports or embeds donor runtime marker ${marker}`);
    }
  }
});

test("future P18 grains remain outside the active SpecGrain registry", () => {
  const dir = join(repo, ".specgrain", "specs");
  const specs = new Set(readdirSync(dir));
  // P18 grains activate sequentially starting at SG-000073, and only after
  // the P17 exit (SG-000072 CLOSED): no gaps, no out-of-order activation,
  // and at most one non-closed grain at a time.
  const sg72 = JSON.parse(readFileSync(join(dir, "SG-000072.json"), "utf8")) as { state: string };
  const p17Exited = sg72.state === "CLOSED";
  let openCount = 0;
  for (let n = 73; n <= 86; n += 1) {
    const id = `SG-${String(n).padStart(6, "0")}.json`;
    if (!specs.has(id)) {
      for (let m = n + 1; m <= 86; m += 1) {
        const later = `SG-${String(m).padStart(6, "0")}.json`;
        assert.equal(specs.has(later), false, `${later} activates out of order`);
      }
      break;
    }
    assert.ok(p17Exited, `${id} must not be activated before the P17 exit`);
    const state = (JSON.parse(readFileSync(join(dir, id), "utf8")) as { state: string }).state;
    assert.ok(state === "GRAIN" || state === "PROVEN" || state === "CLOSED", `${id} has unknown state ${state}`);
    if (state !== "CLOSED") {
      openCount += 1;
    }
  }
  assert.ok(openCount <= 1, `at most one active P18 grain, found ${openCount}`);
});
