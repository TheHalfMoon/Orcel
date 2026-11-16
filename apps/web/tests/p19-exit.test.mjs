import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..");
const repo = join(web, "..", "..");

const read = (path) => readFileSync(join(repo, path), "utf8");
const json = (path) => JSON.parse(read(path));
const sha256 = (path) => createHash("sha256").update(readFileSync(join(repo, path))).digest("hex");

const matrix = json("docs/p19/sg000091_exit_matrix.json");

test("SG-000091 exit matrix is complete and authority-neutral", () => {
  assert.equal(matrix.schema, "deskal-p19-exit-matrix/1");
  assert.equal(matrix.grain, "SG-000091");
  assert.equal(matrix.program, "DESKAL-P19");
  assert.equal(matrix.activation_merge, "064124ce64650de29e69f04d42dbd4ec0a89dbfa");
  assert.equal(matrix.activation_post_merge_ci, "37538199470");
  assert.equal(matrix.authority_delta, "none");
  assert.deepEqual(matrix.classification_vocabulary, ["PROVEN", "OUT_OF_SCOPE", "UNVERIFIED"]);
  assert.ok(matrix.rows.length >= 18);
  assert.equal(matrix.rows.some((row) => row.classification === "UNVERIFIED"), false);
  for (const row of matrix.rows.filter((entry) => entry.required)) {
    assert.equal(row.classification, "PROVEN", row.id);
    assert.ok(row.evidence.length > 0, row.id);
  }
  assert.ok(matrix.exit_invariants.length >= 8);
});

test("P19 predecessor grains stay CLOSED with exact canonical evidence", () => {
  const expected = new Map(matrix.prior_grains.map((entry) => [entry.id, entry]));
  assert.deepEqual([...expected.keys()], ["SG-000087", "SG-000088", "SG-000089", "SG-000090"]);

  for (const [id, pinned] of expected) {
    const spec = json(`.specgrain/specs/${id}.json`);
    assert.equal(spec.state, "CLOSED", id);
    assert.equal(spec.qualified_head, pinned.qualified_head, id);
    assert.equal(spec.implementation_merge, pinned.merge, id);
    assert.equal(spec.post_merge_ci, pinned.post_merge_ci, id);
    assert.equal(spec.canonical_evidence.unresolved_review_threads, 0, id);
  }
});

test("SG-000091 is closed with exact P19 exit evidence", () => {
  const spec = json(".specgrain/specs/SG-000091.json");
  assert.equal(spec.state, "CLOSED");
  assert.equal(spec.program, "DESKAL-P19");
  assert.equal(spec.qualified_head, "eab70d3a14f4fbfcf01ca4f87c69c1df8f6cd733");
  assert.equal(spec.implementation_merge, "e674d4740ab15f39ec524248f8e512e64cb70d06");
  assert.equal(spec.post_merge_ci, "37541526231");
  assert.equal(spec.canonical_evidence.implementation_pr, 238);
  assert.equal(spec.canonical_evidence.unresolved_review_threads, 0);
  assert.equal(spec.canonical_evidence.program_exit, "DESKAL-P19 EXITED");
});

test("brand, static export, and zero-client-runtime locks remain exact", () => {
  assert.equal(
    sha256("apps/web/public/brand/orcel-mark-mask.svg"),
    "56bd8af1c84680e45ff579a130e16949a472e81c6846e475adf6f06f16e92daf"
  );

  const config = read("apps/web/next.config.ts");
  const page = read("apps/web/app/page.tsx");
  assert.match(config, /output:\s*"export"/);
  for (const marker of ['"use client"', "onClick=", "onKeyDown=", "useState(", "useEffect(", "fetch(", "XMLHttpRequest", "WebSocket("]) {
    assert.equal(page.includes(marker), false, marker);
  }
});

test("forbidden hosted-service and telemetry markers remain absent", () => {
  const sources = [
    read("apps/web/app/page.tsx"),
    read("apps/web/app/layout.tsx"),
    read("apps/web/app/globals.css"),
    read("apps/web/next.config.ts")
  ].join("\n").toLowerCase();

  for (const marker of [
    "google-analytics",
    "googletagmanager",
    "posthog",
    "segment.com",
    "mixpanel",
    "sentry",
    "@vercel/analytics",
    "@vercel/speed-insights",
    "stripe",
    "auth0",
    "clerk",
    "supabase",
    "<form",
    "formaction",
    "sendbeacon",
    "document.cookie"
  ]) {
    assert.equal(sources.includes(marker), false, marker);
  }
});

test("Pages deployment contract stays workflow-built, HTTPS-oriented, secret-free, and custom-domain free", () => {
  const workflow = read(".github/workflows/pages.yml");
  assert.doesNotMatch(workflow, /secrets\./);
  assert.doesNotMatch(workflow, /cname:\s*[^\s]/i);
  assert.match(workflow, /test ! -e apps\/web\/public\/CNAME/);
  assert.match(workflow, /https:\/\/thehalfmoon\.github\.io\/Orcel/);

  assert.equal(matrix.live_snapshot.website.url, "https://thehalfmoon.github.io/Deskal/");
  assert.equal(matrix.live_snapshot.website.http_status, 200);
  assert.equal(matrix.live_snapshot.pages.build_type, "workflow");
  assert.equal(matrix.live_snapshot.pages.https_enforced, true);
  assert.equal(matrix.live_snapshot.pages.cname, null);
  assert.deepEqual(matrix.live_snapshot.pages.source, { branch: "main", path: "/" });
});

test("canonical repository metadata matches the live exit snapshot exactly", () => {
  const metadata = json("docs/canonical/REPOSITORY_METADATA.json");
  assert.equal(metadata.description, matrix.live_snapshot.repository.description);
  assert.equal(metadata.homepage, "https://thehalfmoon.github.io/Orcel/");
  assert.equal(matrix.live_snapshot.repository.homepage, "https://thehalfmoon.github.io/Deskal/");
  assert.deepEqual(metadata.topics, matrix.live_snapshot.repository.topics);
});

test("P19 exits remain immutable and P20 activates SG-000096 only after SG-000095 closeout", () => {
  const p19 = read("docs/canonical/ORCEL_POST_P18_LAUNCH_PLAN.md");
  const p20 = read("docs/canonical/ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md");
  const sg91 = json(".specgrain/specs/SG-000091.json");
  const sg92 = json(".specgrain/specs/SG-000092.json");
  const sg93 = json(".specgrain/specs/SG-000093.json");
  const sg94 = json(".specgrain/specs/SG-000094.json");
  const sg95 = json(".specgrain/specs/SG-000095.json");
  const sg96 = json(".specgrain/specs/SG-000096.json");

  assert.match(p19, /Status: EXITED CANONICAL/);
  assert.match(p19, /SG-000091 is CLOSED canonical/);
  assert.equal(sg91.state, "CLOSED");

  assert.match(p20, /Activation grain: SG-000092/);
  assert.equal(sg92.state, "CLOSED");

  assert.equal(sg93.id, "SG-000093");
  assert.equal(sg93.program, "DESKAL-P20");
  assert.equal(sg93.state, "CLOSED");

  assert.equal(sg94.id, "SG-000094");
  assert.equal(sg94.program, "DESKAL-P20");
  assert.equal(sg94.state, "CLOSED");
  assert.equal(sg94.qualified_head, "b0459d356c8397e6cf91126bcdc209f11e41ef11");
  assert.equal(sg94.implementation_merge, "5a86440021d70c8abb021c2042adc6ee1108471e");
  assert.equal(sg94.post_merge_ci, "37651396449");

  assert.equal(sg95.id, "SG-000095");
  assert.equal(sg95.program, "DESKAL-P20");
  assert.equal(sg95.state, "CLOSED");
  assert.equal(sg95.base, "5a86440021d70c8abb021c2042adc6ee1108471e");
  assert.deepEqual(sg95.dependencies, ["SG-000094"]);
  assert.equal(sg95.qualified_head, "1ba3dadf98fbd47bc2f809abb9b68a7cd83ca973");
  assert.equal(sg95.implementation_merge, "be21813d29e4faf4887a9b23f67b2158ce247832");
  assert.equal(sg95.post_merge_ci, "37700649594");

  assert.equal(sg96.id, "SG-000096");
  assert.equal(sg96.program, "DESKAL-P20");
  assert.equal(sg96.state, "GRAIN");
  assert.equal(sg96.base, "7e0f93d11e9be27903d539d2f45bb2aba5fc56c0");
  // The 2026-11-17 continuation adds the authority service and the contracts.
  assert.deepEqual(sg96.dependencies, ["SG-000095", "SG-000132", "SG-000131"]);

  // SG-000097 opened out of order by founder decision FD-UP-4 of 2026-11-17;
  // SG-000098 to SG-000107 stay reserved.
  assert.equal(json(".specgrain/specs/SG-000097.json").state, "GRAIN");
  for (let n = 98; n <= 107; n += 1) {
    const id = `SG-${String(n).padStart(6, "0")}.json`;
    assert.throws(() => read(`.specgrain/specs/${id}`), undefined, id);
  }
});
