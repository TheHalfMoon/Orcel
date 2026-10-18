import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const repo = join(root, "..", "..");

const read = (path) => readFile(path, "utf8");
const sha256 = async (path) =>
  createHash("sha256").update(await readFile(path)).digest("hex");

test("web dependencies are exact-pinned and telemetry is disabled in every Next command", async () => {
  const pkg = JSON.parse(await read(join(root, "package.json")));
  for (const group of ["dependencies", "devDependencies"]) {
    for (const [name, version] of Object.entries(pkg[group] ?? {})) {
      assert.match(version, /^\d+\.\d+\.\d+$/, `${name} must be exact-pinned`);
    }
  }
  for (const command of ["dev", "build", "start"]) {
    assert.match(pkg.scripts[command], /NEXT_TELEMETRY_DISABLED=1/);
  }
});

test("public copy uses Orcel identity and keeps compatibility naming bounded", async () => {
  const page = await read(join(root, "app", "page.tsx"));
  assert.match(page, /Orcel/);
  for (const staleName of ["Cotra", "Qun" + "tal"]) {
    assert.equal(page.includes(staleName), false, `stale product identity: ${staleName}`);
  }
  const orcelMentions = page.match(/orcel/g) ?? [];
  assert.ok(orcelMentions.length >= 2, "the Orcel CLI example and identity note must be explicit");
  assert.match(page, /Identity note/);
});

test("website source contains no analytics, tracking, dynamic service, auth, payment, or form dependency", async () => {
  const sources = [
    await read(join(root, "app", "page.tsx")),
    await read(join(root, "app", "layout.tsx")),
    await read(join(root, "app", "globals.css")),
    await read(join(root, "next.config.ts"))
  ].join("\n").toLowerCase();

  for (const forbidden of [
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
    "xmlhttprequest",
    "sendbeacon",
    "websocket(",
    "document.cookie",
    "fetch("
  ]) {
    assert.equal(sources.includes(forbidden), false, `forbidden hosted dependency marker: ${forbidden}`);
  }
});

test("Next output is a static export with a bounded explicit project base path", async () => {
  const config = await read(join(root, "next.config.ts"));
  assert.match(config, /output:\s*"export"/);
  assert.match(config, /ORCEL_WEB_BASE_PATH/);
  assert.match(config, /basePath,/);
  assert.match(config, /one absolute path segment/);
  assert.doesNotMatch(config, /rewrites|redirects|headers\s*\(|serverRuntimeConfig/);

  const layout = await read(join(root, "app", "layout.tsx"));
  const css = await read(join(root, "app", "globals.css"));
  assert.match(layout, /--orcel-mark-mask/);
  assert.match(layout, /brand\/orcel-o-white\.svg/);
  assert.equal(css.includes('url("/brand/orcel-o-white.svg")'), false);
  assert.equal((css.match(/var\(--orcel-mark-mask\)/g) ?? []).length, 1);
});

test("approved Signal symbol is byte-pinned and keeps the orange terminal", async () => {
  assert.equal(
    await sha256(join(root, "public", "brand", "orcel-o-white.svg")),
    "99c3c4d510147df7b9a043e758ddede7844b91c585547d0ba700a59867e94a58"
  );
  const css = await read(join(root, "app", "globals.css"));
  assert.equal((css.match(/var\(--orcel-mark-mask\)/g) ?? []).length, 1, "all site instances share one full-color SVG");
  assert.match(css, /\.brand-mark-white[\s\S]*color:\s*#fff/);
  assert.match(css, /\.brand-mark[\s\S]*background:\s*var\(--orcel-mark-mask\)/);
});

test("web dependency graph is isolated from runtime workspaces and lockfile", async () => {
  const pkg = JSON.parse(await read(join(repo, "package.json")));
  assert.deepEqual([...pkg.workspaces].sort(), ["apps/orcel-mcp", "apps/orcel-relay"].sort());
  assert.equal(pkg.scripts["web:typecheck"], "npm --prefix apps/web run typecheck");
  assert.equal(pkg.scripts["web:test"], "npm --prefix apps/web run test");
  assert.equal(pkg.scripts["web:build"], "npm --prefix apps/web run build");

  const runtimeLock = JSON.parse(await read(join(repo, "package-lock.json")));
  assert.equal(runtimeLock.packages?.["apps/web"], undefined, "runtime lockfile must not contain the web app");

  const webLock = JSON.parse(await read(join(root, "package-lock.json")));
  assert.equal(webLock.packages?.[""]?.name, "@orcel/web");
  assert.equal(webLock.packages?.[""]?.dependencies?.next, "16.3.8");
  assert.equal(webLock.packages?.[""]?.dependencies?.react, "19.3.0");
  assert.equal(webLock.packages?.[""]?.dependencies?.["react-dom"], "19.3.0");
});

test("public launch links stay on canonical Orcel repository, docs, and Releases surfaces", async () => {
  const page = await read(join(root, "app", "page.tsx"));
  const readme = await read(join(repo, "README.md"));

  assert.match(page, /const github = "https:\/\/github\.com\/TheHalfMoon\/Orcel"/);
  assert.match(page, /const releases = `\$\{github\}\/releases`/);
  assert.match(page, /View verified releases/);
  assert.equal(page.includes("/releases/download/"), false, "website must not link directly to release artifacts");
  assert.equal(page.includes(".zip"), false, "website must not hard-code downloadable archives");

  assert.match(readme, /https:\/\/thehalfmoon\.github\.io\/Orcel\//);
  assert.match(readme, /https:\/\/github\.com\/TheHalfMoon\/Orcel\/releases/);
});

test("Pages workflow is zero-cost, pinned, secret-free, and least-privilege", async () => {
  const workflow = await read(join(repo, ".github", "workflows", "pages.yml"));

  for (const pin of [
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d",
    "actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9",
    "actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346"
  ]) {
    assert.equal(workflow.includes(pin), true, "workflow action must be commit-pinned");
  }

  assert.match(workflow, /contents:\s*read/);
  assert.match(workflow, /pages:\s*read/);
  assert.match(workflow, /pages:\s*write/);
  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, /permissions:\s*\{\}/);
  assert.doesNotMatch(workflow, /secrets\./);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /schedule:/);
  assert.match(workflow, /test ! -e apps\/web\/public\/CNAME/);
  assert.doesNotMatch(workflow, /cname:\s*[^\s]/i);
});

test("Pages workflow builds the canonical project path and verifies the deployed HTTPS site", async () => {
  const workflow = await read(join(repo, ".github", "workflows", "pages.yml"));

  assert.match(workflow, /ORCEL_WEB_BASE_PATH/);
  assert.match(workflow, /base_path/);
  assert.match(workflow, /test "\$\{\{ steps\.pages\.outputs\.base_path \}\}" = "\/Orcel"/);
  assert.match(workflow, /\/Orcel\/_next\//);
  assert.match(workflow, /\/Orcel\/brand\/orcel-o-white\.svg/);
  assert.match(workflow, /A clear signal\./);
  assert.match(workflow, /orcel-wordmark-white\.svg/);
  assert.match(workflow, /Orcel Signal Identity 2026/);
  assert.match(workflow, /https:\/\/thehalfmoon\.github\.io\/Orcel/);
  assert.match(workflow, /curl --fail --location/);
  assert.match(workflow, /https:\/\/github\.com\/TheHalfMoon\/Orcel\/releases/);
});

test("canonical repository metadata is exact, bounded, and aligned with public entrypoints", async () => {
  const metadata = JSON.parse(await read(join(repo, "docs", "canonical", "REPOSITORY_METADATA.json")));
  const page = await read(join(root, "app", "page.tsx"));
  const readme = await read(join(repo, "README.md"));

  assert.deepEqual(Object.keys(metadata).sort(), ["description", "homepage", "repository", "topics"]);
  assert.equal(metadata.repository, "TheHalfMoon/Orcel");
  assert.equal(
    metadata.description,
    "Local-first MCP authority layer for safe, bounded computer use and developer workflows."
  );
  assert.equal(metadata.homepage, "https://thehalfmoon.github.io/Orcel/");
  assert.deepEqual(metadata.topics, [
    "ai-agents",
    "computer-use",
    "desktop-automation",
    "local-first",
    "mcp",
    "mcp-server",
    "windows"
  ]);
  assert.equal(new Set(metadata.topics).size, metadata.topics.length, "topics must be unique");

  assert.equal(readme.includes(`**Website:** ${metadata.homepage}`), true);
  assert.equal(page.includes("https://github.com/TheHalfMoon/Orcel"), true);
  assert.equal(page.includes("/releases/download/"), false);
});


test("canonical and social metadata stay exact, static, and bounded to the Pages identity", async () => {
  const layout = await read(join(root, "app", "layout.tsx"));

  assert.match(layout, /const siteUrl = "https:\/\/thehalfmoon\.github\.io\/Orcel\/"/);
  assert.match(layout, /metadataBase:\s*new URL\(siteUrl\)/);
  assert.match(layout, /alternates:\s*\{[\s\S]*canonical:\s*siteUrl[\s\S]*\}/);
  assert.match(layout, /openGraph:\s*\{[\s\S]*url:\s*siteUrl[\s\S]*siteName:\s*"Orcel"/);
  assert.match(layout, /twitter:\s*\{[\s\S]*card:\s*"summary"[\s\S]*title[\s\S]*description/);
  assert.equal((layout.match(/https:\/\/thehalfmoon\.github\.io\/Orcel\//g) ?? []).length, 1);
  assert.equal((layout.match(/images:\s*\[/g) ?? []).length, 2, "only the two static local image declarations are allowed");
  assert.match(layout, /images:\s*\[\{\s*url:\s*siteUrl \+ "brand\/orcel-social-dark\.png"/);
  assert.match(layout, /images:\s*\[siteUrl \+ "brand\/orcel-social-dark\.png"\]/);
  const og = await readFile(join(root, "public", "brand", "orcel-social-dark.png"));
  assert.equal(og.subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
  assert.equal(og.readUInt32BE(16), 1200);
  assert.equal(og.readUInt32BE(20), 630);
});

test("responsive primary navigation stays keyboard and touch usable without client runtime", async () => {
  const page = await read(join(root, "app", "page.tsx"));
  const css = await read(join(root, "app", "globals.css"));

  assert.match(page, /<nav className="desktop-nav" aria-label="Primary navigation">/);
  assert.match(page, /<details className="mobile-nav">/);
  assert.match(page, /<summary aria-label="Toggle primary navigation">/);
  assert.match(page, /<nav className="mobile-nav-panel" aria-label="Mobile primary navigation">/);
  assert.match(page, /<div id="content" tabIndex=\{-1\}>/);

  for (const marker of ['"use client"', "onClick=", "onKeyDown=", "useState(", "useEffect("]) {
    assert.equal(page.includes(marker), false, `static navigation must not add client behavior: ${marker}`);
  }

  assert.match(css, /a:focus-visible,\s*summary:focus-visible/);
  assert.match(css, /\.mobile-nav summary\s*\{[\s\S]*min-height:\s*44px/);
  assert.match(css, /\.mobile-nav-panel a\s*\{[\s\S]*min-height:\s*48px/);
  assert.match(css, /@media \(max-width: 960px\)[\s\S]*\.mobile-nav\s*\{\s*display:\s*block/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[\s\S]*scroll-behavior:\s*auto/);
});
