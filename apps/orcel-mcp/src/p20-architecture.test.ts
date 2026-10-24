import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");

interface Donor {
  id: string;
  repository: string;
  revision: string;
  license: string;
  owner_grains: string[];
  runtime_imported: boolean;
  permission_gate: string;
}

interface ArchitectureFreeze {
  schema: string;
  grain: string;
  program: string;
  canonical_base: string;
  activation: {
    pr: number;
    base: string;
    qualified_head: string;
    pre_merge_ci: string;
    review_gates: string;
    merge_sha: string;
    post_merge_ci: string;
    pages_run: string;
    jev: { expected_hunks: number; reviewed_hunks: number; findings: number; blocking_findings: number };
    ocr: { reviewable_files: number; excluded_files: number; manual_exclusions_reviewed: number; blocking_findings: number };
    unresolved_review_threads: number;
  };
  authority_delta: string;
  caller_facing_authority: string;
  authority_modes: Array<{ id: string; default: boolean; grantor: string; privilege: string; self_grant: boolean }>;
  privilege_denials: string[];
  execution_preference: string[];
  result_states: string[];
  private_hosts: Array<{ id: string; donor_id: string; owner_grains: string[]; caller_facing: boolean }>;
  donors: Donor[];
  grain_sequence: Array<{ id: string; role: string }>;
  import_state: {
    donor_files_imported: string[];
    runtime_dependencies_added: string[];
    mcp_tools_added: string[];
    privileged_services_added: string[];
    releases_or_tags_mutated: boolean;
  };
  invariants: string[];
}

const read = (path: string): string => readFileSync(join(repo, path), "utf8");
const readJson = <T>(path: string): T => JSON.parse(read(path)) as T;
const freeze = readJson<ArchitectureFreeze>("docs/p20/sg000092_architecture_freeze.json");

const EXPECTED_DONORS: Record<string, { repository: string; revision: string; licenseNeedle: string }> = {
  open_computer_use: {
    repository: "opensymph/open-computer-use",
    revision: "5b433b98019c18201a15d11e8c3cb0010879a3d8",
    licenseNeedle: "MIT"
  },
  desktop_commander: {
    repository: "wonderwhy-er/DesktopCommanderMCP",
    revision: "bc1e944e30302e0022d49f418d55563dd74a162c",
    licenseNeedle: "MIT"
  },
  firecrawl: {
    repository: "firecrawl/firecrawl",
    revision: "7120d16926544483513782b5393ae9850691d52a",
    licenseNeedle: "AGPL-3.0"
  },
  agent_reach: {
    repository: "Panniantong/Agent-Reach",
    revision: "a19a171fa980a0785849596492e0af4db800c82f",
    licenseNeedle: "MIT"
  },
  ui_tars: {
    repository: "bytedance/UI-TARS-desktop",
    revision: "2ff41a9e515828c5bd5b276e493d73aa0bdf4a3a",
    licenseNeedle: "Apache-2.0"
  },
  gsudo: {
    repository: "gerardog/gsudo",
    revision: "a4eda9b263d72a3e174f73b6b6b3ecfc5bc6656b",
    licenseNeedle: "MIT"
  }
};

test("SG-000092 activation evidence is exact and authority-neutral", () => {
  assert.equal(freeze.schema, "deskal-p20-architecture-freeze/1");
  assert.equal(freeze.grain, "SG-000092");
  assert.equal(freeze.program, "DESKAL-P20");
  assert.equal(freeze.canonical_base, "ed82cb4c976d4169fd4f81327be62d37dd5ea0a7");
  assert.equal(freeze.activation.pr, 241);
  assert.equal(freeze.activation.base, "835200a90fd47425ff3ad40b5b8815dc8ad7871c");
  assert.equal(freeze.activation.qualified_head, "771eaaeba234b1f533fd849440e133ff03ef62ae");
  assert.equal(freeze.activation.pre_merge_ci, "37547623637");
  assert.equal(freeze.activation.review_gates, "37547623682");
  assert.equal(freeze.activation.merge_sha, "ed82cb4c976d4169fd4f81327be62d37dd5ea0a7");
  assert.equal(freeze.activation.post_merge_ci, "37548262164");
  assert.equal(freeze.activation.pages_run, "37548261888");
  assert.deepEqual(freeze.activation.jev, { expected_hunks: 8, reviewed_hunks: 8, findings: 0, blocking_findings: 0 });
  assert.deepEqual(freeze.activation.ocr, { reviewable_files: 2, excluded_files: 4, manual_exclusions_reviewed: 4, blocking_findings: 0 });
  assert.equal(freeze.activation.unresolved_review_threads, 0);
  assert.equal(freeze.authority_delta, "none");
});

test("all six donor pins are exact, import-neutral, and obligation-bearing", () => {
  assert.equal(freeze.donors.length, 6);
  assert.deepEqual(freeze.donors.map((entry) => entry.id).sort(), Object.keys(EXPECTED_DONORS).sort());

  const ledger = read("docs/canonical/ORCEL_P20_DONOR_LEDGER.md");
  for (const donor of freeze.donors) {
    const expected = EXPECTED_DONORS[donor.id];
    assert.ok(expected, donor.id);
    assert.equal(donor.repository, expected.repository, donor.id);
    assert.equal(donor.revision, expected.revision, donor.id);
    assert.match(donor.revision, /^[0-9a-f]{40}$/, donor.id);
    assert.ok(donor.license.includes(expected.licenseNeedle), donor.id);
    assert.equal(donor.runtime_imported, false, donor.id);
    assert.ok(donor.permission_gate.length > 20, donor.id);
    assert.ok(donor.owner_grains.length > 0, donor.id);
    assert.ok(ledger.includes(donor.repository), donor.id);
    assert.ok(ledger.includes(donor.revision), donor.id);
  }

  const firecrawl = freeze.donors.find((entry) => entry.id === "firecrawl");
  assert.ok(firecrawl);
  assert.match(firecrawl.permission_gate, /direct-permission evidence/i);
  assert.match(firecrawl.permission_gate, /third-party dependencies/i);
});

test("authority modes are exact and none can self-grant", () => {
  assert.deepEqual(
    freeze.authority_modes.map((entry) => entry.id),
    ["safe", "full_user", "full_admin", "persistent_admin", "remote_full_control"]
  );
  assert.equal(freeze.authority_modes.filter((entry) => entry.default).length, 1);
  assert.equal(freeze.authority_modes[0]?.id, "safe");
  for (const mode of freeze.authority_modes) {
    assert.equal(mode.self_grant, false, mode.id);
    assert.ok(mode.grantor.length > 0, mode.id);
    assert.ok(mode.privilege.length > 0, mode.id);
  }

  const fullAdmin = freeze.authority_modes.find((entry) => entry.id === "full_admin");
  assert.ok(fullAdmin);
  assert.match(fullAdmin.grantor, /Windows elevation/);
  assert.match(fullAdmin.privilege, /OS-issued elevated administrator token/);

  for (const denied of ["UAC bypass", "Windows Hello bypass", "secure-desktop automation", "model self-grant", "remote self-grant"]) {
    assert.ok(freeze.privilege_denials.includes(denied), denied);
  }
});

test("P20 subsystem ownership and sequence have no gap", () => {
  const ids = freeze.grain_sequence.map((entry) => entry.id);
  assert.deepEqual(ids, Array.from({ length: 16 }, (_, index) => `SG-${String(index + 92).padStart(6, "0")}`));
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(freeze.private_hosts.length, 6);
  assert.equal(freeze.private_hosts.every((host) => host.caller_facing === false), true);
  assert.deepEqual(
    freeze.private_hosts.map((host) => host.donor_id).sort(),
    Object.keys(EXPECTED_DONORS).sort()
  );

  const plan = read("docs/canonical/ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md");
  for (const entry of freeze.grain_sequence) {
    assert.ok(plan.includes(entry.id), entry.id);
    assert.ok(entry.role.length > 0, entry.id);
  }
  assert.equal(plan.includes("SG-000108"), false);
});

test("SG-000094 and SG-000095 are closed and SG-000096 is the only active P20 grain", () => {
  const specDir = join(repo, ".specgrain", "specs");
  const specs = readdirSync(specDir).filter((name) => /^SG-\d{6}\.json$/.test(name));
  const open: string[] = [];
  for (const name of specs) {
    const spec = JSON.parse(readFileSync(join(specDir, name), "utf8")) as { id: string; state: string };
    if (spec.state !== "CLOSED") {
      open.push(spec.id);
    }
  }
  // SG-000108 (ORCEL-F3) ran in parallel by founder decision (issue #290)
  // and SG-000126 (ORCEL-F2) followed it by founder sequencing (issue #435);
  // both are outside DESKAL-P20 and closed, and no other grain may be open.
  assert.deepEqual(open.sort(), ["SG-000096"]);
  const sg126 = readJson<{
    program: string;
    state: string;
    planning_issue: number;
    implementation_pr: number;
    qualified_head: string;
    qualified_tree: string;
    implementation_merge: string;
    authority_delta: { activation: string; network: string; process: string; privileged: string };
  }>(".specgrain/specs/SG-000126.json");
  assert.equal(sg126.program, "ORCEL-F2");
  assert.equal(sg126.state, "CLOSED");
  assert.equal(sg126.planning_issue, 435);
  assert.equal(sg126.implementation_pr, 437);
  assert.equal(sg126.qualified_head, "80ea357437d7d3bb1c61de85d1e509e2e17d8a46");
  assert.equal(sg126.qualified_tree, "db4f96a8d88d4ffbc3f4b0a1838cf9968e8be6de");
  assert.equal(sg126.implementation_merge, "41fcb6e8fc2d5edfc1ce1a4f65b32f4c0ef2d994");
  for (const key of ["activation", "network", "process", "privileged"] as const) {
    assert.ok(sg126.authority_delta[key].startsWith("None."), key);
  }
  const sg108 = readJson<{
    program: string;
    state: string;
    planning_issue: number;
    implementation_pr: number;
    qualified_head: string;
    qualified_tree: string;
    implementation_merge: string;
    post_merge_ci: string;
    authority_delta: { activation: string; privileged: string; ui_input: string };
  }>(".specgrain/specs/SG-000108.json");
  assert.equal(sg108.program, "ALADDIN-F3");
  assert.equal(sg108.state, "CLOSED");
  assert.equal(sg108.planning_issue, 290);
  assert.equal(sg108.implementation_pr, 433);
  assert.equal(sg108.qualified_head, "17ebbf846423485bda201fdf4fc45cfd34e7846c");
  assert.equal(sg108.qualified_tree, "e74318cad8e03036b9d9df2ed0984ef8302f1752");
  assert.equal(sg108.implementation_merge, "d94b88cd44ae0a6a0285c41f66c3f6e3dea4e203");
  assert.equal(sg108.post_merge_ci, "39862151758");
  // The parallel activation grants nothing by itself.
  for (const key of ["activation", "privileged", "ui_input"] as const) {
    assert.ok(sg108.authority_delta[key].startsWith("None."), key);
  }

  const sg94 = readJson<{
    state: string;
    qualified_head: string;
    implementation_merge: string;
    post_merge_ci: string;
    canonical_evidence: { implementation_pr: number; qualified_tree: string; unresolved_review_threads: number };
  }>(".specgrain/specs/SG-000094.json");
  assert.equal(sg94.state, "CLOSED");
  assert.equal(sg94.qualified_head, "b0459d356c8397e6cf91126bcdc209f11e41ef11");
  assert.equal(sg94.implementation_merge, "5a86440021d70c8abb021c2042adc6ee1108471e");
  assert.equal(sg94.post_merge_ci, "37651396449");
  assert.equal(sg94.canonical_evidence.implementation_pr, 254);
  assert.equal(sg94.canonical_evidence.qualified_tree, "37e086ca4196bd4674cbe6bb87815cc1c32590b5");
  assert.equal(sg94.canonical_evidence.unresolved_review_threads, 0);

  const sg95 = readJson<{
    id: string;
    program: string;
    state: string;
    base: string;
    dependencies: string[];
    qualified_head: string;
    qualified_tree: string;
    implementation_merge: string;
    pre_merge_ci: string;
    pre_merge_review_gates: string;
    post_merge_ci: string;
    canonical_evidence: { signed_dco_commits: number; unresolved_review_threads: number };
  }>(".specgrain/specs/SG-000095.json");
  assert.equal(sg95.id, "SG-000095");
  assert.equal(sg95.program, "DESKAL-P20");
  assert.equal(sg95.state, "CLOSED");
  assert.equal(sg95.base, "5a86440021d70c8abb021c2042adc6ee1108471e");
  assert.deepEqual(sg95.dependencies, ["SG-000094"]);
  assert.equal(sg95.qualified_head, "1ba3dadf98fbd47bc2f809abb9b68a7cd83ca973");
  assert.equal(sg95.qualified_tree, "a383cc7cbff4e252a5c331734d646bab7c196166");
  assert.equal(sg95.implementation_merge, "be21813d29e4faf4887a9b23f67b2158ce247832");
  assert.equal(sg95.pre_merge_ci, "37699286110");
  assert.equal(sg95.pre_merge_review_gates, "37699282497");
  assert.equal(sg95.post_merge_ci, "37700649594");
  assert.equal(sg95.canonical_evidence.signed_dco_commits, 3);
  assert.equal(sg95.canonical_evidence.unresolved_review_threads, 0);

  const sg96 = readJson<{ id: string; title: string; program: string; state: string; base: string; dependencies: string[]; planning_issue: number; authority_delta: { activation: string; safe: string }; scope: { exclude: string[] } }>(".specgrain/specs/SG-000096.json");
  assert.equal(sg96.id, "SG-000096");
  assert.equal(sg96.title, "Shell and process sessions");
  assert.equal(sg96.program, "DESKAL-P20");
  assert.equal(sg96.state, "GRAIN");
  assert.equal(sg96.base, "7e0f93d11e9be27903d539d2f45bb2aba5fc56c0");
  assert.deepEqual(sg96.dependencies, ["SG-000095"]);
  assert.equal(sg96.planning_issue, 260);
  assert.match(sg96.authority_delta.activation, /^None\./);
  assert.match(sg96.authority_delta.safe, /Unchanged:/);
  assert.ok(sg96.scope.exclude.some(item => item.includes("Full Admin")));

  for (let n = 97; n <= 107; n += 1) {
    const id = `SG-${String(n).padStart(6, "0")}.json`;
    assert.equal(specs.includes(id), false, id);
  }
});


test("SG-000096 donor freeze is attributable, local-only and not executable at activation", () => {
  const manifest = readJson<{
    schema: string;
    grain: string;
    activation_base: string;
    source_issue: number;
    donor: { repository: string; commit: string; license: string; license_blob_sha: string };
    selected: Array<{ source: string; blob: string; reuse: string; destination: string }>;
    reused_deskal: string[];
    excluded_features: string[];
    authority_profile: { safe: string; full_user: string; full_admin: boolean; persistent_admin: boolean; remote_full_control: boolean; delegated_mcp_self_grant: boolean };
    activation_state: { donor_runtime_imported: boolean; local_shell_executor_implemented: boolean; full_user_shell_authority_enabled: boolean; mcp_tools_added: string[]; new_dependencies: string[]; new_listeners: string[]; release_payload_changed: boolean };
  }>("docs/p20/sg000096_shell_session_import.json");
  assert.equal(manifest.schema, "deskal-p20-sg000096-shell-session-import/1");
  assert.equal(manifest.grain, "SG-000096");
  assert.equal(manifest.activation_base, "7e0f93d11e9be27903d539d2f45bb2aba5fc56c0");
  assert.equal(manifest.source_issue, 260);
  assert.deepEqual(
    [manifest.donor.repository, manifest.donor.commit, manifest.donor.license, manifest.donor.license_blob_sha],
    ["wonderwhy-er/DesktopCommanderMCP", "bc1e944e30302e0022d49f418d55563dd74a162c", "MIT", "cc6ce4fa68f26cd5db3dc1ff83c8163094f28451"]
  );
  assert.deepEqual(
    manifest.selected.map(({ source, blob }) => [source, blob]),
    [
      ["src/terminal-manager.ts", "528e2872754315751dc1559922bbf9764cdcd702"],
      ["src/handlers/terminal-handlers.ts", "1f6930fdd6dcf28aebecd99036eab2585edaac23"],
      ["src/handlers/process-handlers.ts", "fef82042b75324d6ccf7ab566f737daad5c09487"],
      ["src/tools/improved-process-tools.ts", "92bad49daf49230a60483fcc6a798802218d2e36"],
      ["src/tools/process.ts", "c91bcc7c831fbb9466847c2a4ebe159a1d6be74e"],
      ["src/utils/process-detection.ts", "a58b500eed84865af8d37ae61120bd8a540a2ca8"]
    ]
  );
  assert.ok(manifest.selected.every(entry => /^(COPY_ADAPT|PORT|REFERENCE)$/.test(entry.reuse)));
  assert.ok(manifest.reused_deskal.includes("crates/qdral-provider-process/src/lib.rs"));
  assert.ok(manifest.reused_deskal.includes("crates/qdral-policy/src/full_control_store.rs"));
  assert.ok(manifest.excluded_features.some(entry => entry.includes("node:local")));
  assert.ok(manifest.excluded_features.some(entry => entry.includes("remote")));
  assert.match(manifest.authority_profile.safe, /no widening/);
  assert.equal(manifest.authority_profile.full_admin, false);
  assert.equal(manifest.authority_profile.persistent_admin, false);
  assert.equal(manifest.authority_profile.remote_full_control, false);
  assert.equal(manifest.authority_profile.delegated_mcp_self_grant, false);
  assert.equal(manifest.activation_state.donor_runtime_imported, false);
  assert.equal(manifest.activation_state.local_shell_executor_implemented, false);
  assert.equal(manifest.activation_state.full_user_shell_authority_enabled, false);
  assert.deepEqual(manifest.activation_state.mcp_tools_added, []);
  assert.deepEqual(manifest.activation_state.new_dependencies, []);
  assert.deepEqual(manifest.activation_state.new_listeners, []);
  assert.equal(manifest.activation_state.release_payload_changed, false);
});

test("SG-000094 donor selection is exact and keeps input paths deferred", () => {
  const manifest = readJson<{
    schema: string;
    grain: string;
    donor: { repository: string; commit: string; commit_verified: boolean; license: string; license_blob_sha: string };
    selected: Array<{ source: string; reuse: string; destination: string }>;
    deferred_to_sg_000095: Array<{ source: string }>;
    dependencies: { go: string; modules: Array<{ module: string; version: string; license: string; license_blob_sha: string; notice_path: string }>; explicitly_not_selected: string[] };
    private_protocol: { operations: string[]; caller_facing: boolean; listeners: string[]; network_egress: boolean; desktop_input: boolean; app_launch: boolean; focus_mutation: boolean; privileged: boolean };
    packaging: { included_in_release: boolean; owner_for_unified_packaging: string };
  }>("docs/p20/sg000094_windows_host_import.json");

  assert.equal(manifest.schema, "deskal-p20-sg000094-host-import/1");
  assert.equal(manifest.grain, "SG-000094");
  assert.equal(manifest.donor.repository, "opensymph/open-computer-use");
  assert.equal(manifest.donor.commit, "5b433b98019c18201a15d11e8c3cb0010879a3d8");
  assert.equal(manifest.donor.commit_verified, true);
  assert.equal(manifest.donor.license, "MIT");
  assert.equal(manifest.donor.license_blob_sha, "3b3840d939919f58113a626bb990a90f3b949aab");

  assert.deepEqual(
    manifest.selected.map((entry) => entry.source),
    [
      "apps/OpenComputerUseWindows/native_capture.go",
      "apps/OpenComputerUseWindows/native_uia.go",
      "apps/OpenComputerUseWindows/native_win32.go",
      "apps/OpenComputerUseWindows/native_op_client.go",
      "apps/OpenComputerUseWindows/native_backend.go",
      "apps/OpenComputerUseWindows/main.go"
    ]
  );
  assert.deepEqual(
    manifest.deferred_to_sg_000095.map((entry) => entry.source),
    [
      "apps/OpenComputerUseWindows/native_actions.go",
      "apps/OpenComputerUseWindows/desktop_windows.go",
      "apps/OpenComputerUseWindows/input_helpers.go",
      "apps/OpenComputerUseWindows/desktop.go"
    ]
  );
  assert.deepEqual(manifest.dependencies.modules, [{
    module: "golang.org/x/sys",
    version: "v0.47.0",
    license: "BSD-3-Clause",
    license_blob_sha: "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4",
    notice_path: "docs/p20/notices/golang-x-sys-BSD-3-Clause.txt"
  }]);
  assert.deepEqual(manifest.dependencies.explicitly_not_selected, ["golang.org/x/image"]);
  assert.deepEqual(manifest.private_protocol.operations, [
    "hello",
    "ping",
    "list_windows",
    "observe_window",
    "capture_window",
    "shutdown"
  ]);
  assert.equal(manifest.private_protocol.caller_facing, false);
  assert.deepEqual(manifest.private_protocol.listeners, []);
  assert.equal(manifest.private_protocol.network_egress, false);
  assert.equal(manifest.private_protocol.desktop_input, false);
  assert.equal(manifest.private_protocol.app_launch, false);
  assert.equal(manifest.private_protocol.focus_mutation, false);
  assert.equal(manifest.private_protocol.privileged, false);
  assert.equal(manifest.packaging.included_in_release, false);
  assert.equal(manifest.packaging.owner_for_unified_packaging, "SG-000106");
});

test("SG-000095 donor selection is exact, reuse-first, and rejects recording/privilege widening", () => {
  const manifest = readJson<{
    schema: string;
    grain: string;
    activation_base: string;
    donor: { repository: string; commit: string; license: string; license_blob_sha: string };
    selected: Array<{ source: string; blob: string; reuse: string; destination: string }>;
    private_protocol: {
      base_operations: string[];
      authorized_successor_operations: string[];
      caller_facing: boolean;
      listeners: string[];
      network_egress: boolean;
      requires_full_control_lease: boolean;
      allowed_modes: string[];
      safe_mode_input: boolean;
      privileged: boolean;
    };
    explicitly_rejected: string[];
    dependencies: { modules: Array<{ module: string; version: string }>; new_modules_at_activation: string[] };
    packaging: { included_in_release: boolean; owner_for_unified_packaging: string };
    activation_state: { donor_runtime_imported: boolean; mcp_tools_added: string[]; host_operations_added: string[]; authority_executable: boolean };
    implementation_state: {
      implementation_base: string;
      donor_runtime_imported: boolean;
      imported_runtime_files: string[];
      host_operations_added: string[];
      mcp_tools_added: string[];
      local_full_user_authority_store: boolean;
      local_grant_requires_strong_presence: boolean;
      remote_dispatch_denied: boolean;
      full_admin_execution: boolean;
      persistent_admin: boolean;
      remote_full_control: boolean;
      privileged: boolean;
      network_listener: boolean;
      packaged: boolean;
      native_windows_qualification: string;
    };
  }>("docs/p20/sg000095_desktop_input_import.json");

  assert.equal(manifest.schema, "deskal-p20-sg000095-desktop-input-import/1");
  assert.equal(manifest.grain, "SG-000095");
  assert.equal(manifest.activation_base, "5a86440021d70c8abb021c2042adc6ee1108471e");
  assert.equal(manifest.donor.repository, "opensymph/open-computer-use");
  assert.equal(manifest.donor.commit, "5b433b98019c18201a15d11e8c3cb0010879a3d8");
  assert.equal(manifest.donor.license, "MIT");
  assert.equal(manifest.donor.license_blob_sha, "3b3840d939919f58113a626bb990a90f3b949aab");
  assert.deepEqual(
    manifest.selected.map((entry) => [entry.source, entry.blob, entry.reuse]),
    [
      ["apps/OpenComputerUseWindows/native_actions.go", "25c2482d9d0e6b82c890ecf07956643b88bbf97f", "COPY_ADAPT"],
      ["apps/OpenComputerUseWindows/native_win32.go", "e94ce44c7e76ce45035dfe584c883cab16babdf0", "COPY_ADAPT"],
      ["apps/OpenComputerUseWindows/desktop_windows.go", "59466d669c1bfea13a15dfc371d9eceb471f21bd", "COPY_ADAPT"],
      ["apps/OpenComputerUseWindows/input_helpers.go", "a41a65cabfda87ced036fe8ad05b25cd17729dc6", "COPY_ADAPT"],
      ["apps/OpenComputerUseWindows/desktop.go", "39512b3d0ca5e18b07e5f1c31c658198b74dfe84", "REFERENCE"]
    ]
  );
  assert.deepEqual(manifest.private_protocol.base_operations, [
    "hello", "ping", "list_windows", "observe_window", "capture_window", "shutdown"
  ]);
  assert.deepEqual(manifest.private_protocol.authorized_successor_operations, [
    "cursor_position",
    "semantic_action",
    "window_action",
    "input_move",
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
    "input_hotkey"
  ]);
  assert.equal(manifest.private_protocol.caller_facing, false);
  assert.deepEqual(manifest.private_protocol.listeners, []);
  assert.equal(manifest.private_protocol.network_egress, false);
  assert.equal(manifest.private_protocol.requires_full_control_lease, true);
  assert.deepEqual(manifest.private_protocol.allowed_modes, ["full_user"]);
  assert.equal(manifest.private_protocol.safe_mode_input, false);
  assert.equal(manifest.private_protocol.privileged, false);
  assert.ok(manifest.explicitly_rejected.some((entry) => /record\/ffmpeg/i.test(entry)));
  assert.ok(manifest.explicitly_rejected.some((entry) => /UAC\/Windows Hello\/secure-desktop bypass/i.test(entry)));
  assert.deepEqual(manifest.dependencies.modules, [{ module: "golang.org/x/sys", version: "v0.47.0" }]);
  assert.deepEqual(manifest.dependencies.new_modules_at_activation, []);
  assert.equal(manifest.packaging.included_in_release, false);
  assert.equal(manifest.packaging.owner_for_unified_packaging, "SG-000106");
  assert.equal(manifest.activation_state.donor_runtime_imported, false);
  assert.deepEqual(manifest.activation_state.mcp_tools_added, []);
  assert.deepEqual(manifest.activation_state.host_operations_added, []);
  assert.equal(manifest.activation_state.authority_executable, false);

  assert.equal(manifest.implementation_state.implementation_base, "941dfd504e75b578c091e8819ef949bcce8029ad");
  assert.equal(manifest.implementation_state.donor_runtime_imported, true);
  assert.deepEqual(manifest.implementation_state.imported_runtime_files, [
    "apps/deskal-computer-host/native_actions_windows.go",
    "apps/deskal-computer-host/native_input_windows.go",
    "apps/deskal-computer-host/native_window_actions_windows.go"
  ]);
  assert.deepEqual(manifest.implementation_state.host_operations_added, [
    "cursor_position",
    "semantic_action",
    "window_action",
    "input_move",
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
    "input_hotkey"
  ]);
  assert.deepEqual(manifest.implementation_state.mcp_tools_added, [
    "desktop_cursor_get",
    "desktop_element_invoke",
    "desktop_element_scroll",
    "desktop_element_select",
    "desktop_element_set_value",
    "desktop_element_toggle",
    "desktop_input_execute",
    "desktop_window_action",
    "desktop_window_capture"
  ]);
  assert.equal(manifest.implementation_state.local_full_user_authority_store, true);
  assert.equal(manifest.implementation_state.local_grant_requires_strong_presence, true);
  assert.equal(manifest.implementation_state.remote_dispatch_denied, true);
  assert.equal(manifest.implementation_state.full_admin_execution, false);
  assert.equal(manifest.implementation_state.persistent_admin, false);
  assert.equal(manifest.implementation_state.remote_full_control, false);
  assert.equal(manifest.implementation_state.privileged, false);
  assert.equal(manifest.implementation_state.network_listener, false);
  assert.equal(manifest.implementation_state.packaged, false);
  assert.equal(manifest.implementation_state.native_windows_qualification, "required_on_exact_staging_head");
});

test("the frozen execution and result vocabularies stay exact", () => {
  assert.deepEqual(freeze.execution_preference, [
    "semantic_uia_or_native",
    "browser_dom_or_accessibility",
    "visual_grounding",
    "coordinate_or_raw_foreground_input"
  ]);
  assert.deepEqual(freeze.result_states, [
    "not_started",
    "dispatched",
    "completed",
    "cancelled",
    "outcome_unknown"
  ]);
  assert.ok(freeze.invariants.length >= 9);
});

test("SG-000092 imports no donor runtime, dependency, tool, or privileged service", () => {
  assert.deepEqual(freeze.import_state.donor_files_imported, []);
  assert.deepEqual(freeze.import_state.runtime_dependencies_added, []);
  assert.deepEqual(freeze.import_state.mcp_tools_added, []);
  assert.deepEqual(freeze.import_state.privileged_services_added, []);
  assert.equal(freeze.import_state.releases_or_tags_mutated, false);

  const manifests = [
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "Cargo.lock",
    "apps/orcel-mcp/package.json",
    "apps/orcel-relay/package.json"
  ].map(read).join("\n").toLowerCase();

  for (const marker of [
    "desktopcommandermcp",
    "open-computer-use",
    "firecrawl/firecrawl",
    "agent-reach",
    "@ui-tars",
    "ui-tars-desktop",
    "gerardog/gsudo"
  ]) {
    assert.equal(manifests.includes(marker), false, marker);
  }
});

test("canonical P20 documents match the machine-readable freeze", () => {
  const plan = read("docs/canonical/ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md");
  const ledger = read("docs/canonical/ORCEL_P20_DONOR_LEDGER.md");
  const current = read("docs/canonical/CURRENT.md");
  const planning = read("docs/canonical/PLANNING_INDEX.md");

  assert.match(plan, /Activation grain: SG-000092/);
  assert.match(plan, /Planning base: `835200a90fd47425ff3ad40b5b8815dc8ad7871c`/);
  for (const title of ["Safe", "Full User", "Full Admin", "Persistent Admin", "Remote Full Control"]) {
    assert.ok(plan.includes(title), title);
  }
  assert.match(plan, /UAC bypass/);
  assert.match(plan, /Windows Hello bypass/);
  assert.match(plan, /No donor import or authority delta/);

  assert.match(ledger, /Owner grain: SG-000092/);
  assert.match(ledger, /No donor code merge proceeds unless all boxes are proven/);

  assert.match(current, /SG-000094 - Windows Computer Host import - is CLOSED canonical/);
  assert.match(current, /SG-000095 - Desktop input and full computer-control surface - is CLOSED canonical/);
  assert.match(planning, /\.specgrain\/specs\/SG-000095\.json/);
  assert.match(planning, /sg000095_desktop_input_import\.json/);
  assert.match(planning, /sg000094_windows_host_import\.json/);
  assert.match(planning, /ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN\.md/);
  assert.match(planning, /ORCEL_P20_DONOR_LEDGER\.md/);
});
