// The MCP edge as a package ships it: the runtime package.json, the built
// JavaScript without tests, and exactly the locked production dependency closure
// from the repository's node_modules (installed by `npm ci` from
// package-lock.json). Nothing is resolved or downloaded at packaging time, so the
// payload matches the versions and integrity hashes that CI tested.
//
// Used by scripts/package-release.mjs (Windows), and from the shell by the
// unsigned development tarballs:
//   node scripts/mcp-payload.mjs <directory>

import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/// Writes the edge to `<out>/app/orcel-mcp`. `fail` reports and must not return.
export function stageMcpPayload(repo, out, fail) {
  const appSource = join(repo, "apps/orcel-mcp");
  const appOut = join(out, "app/orcel-mcp");
  mkdirSync(join(appOut, "dist"), { recursive: true });
  const pkg = JSON.parse(readFileSync(join(appSource, "package.json"), "utf8"));
  const runtimePackage = {
    name: pkg.name,
    version: pkg.version,
    private: true,
    type: pkg.type,
    engines: pkg.engines,
    dependencies: pkg.dependencies
  };
  writeFileSync(join(appOut, "package.json"), `${JSON.stringify(runtimePackage, null, 2)}\n`);
  const distSource = join(appSource, "dist");
  if (!existsSync(join(distSource, "index.js"))) fail("apps/orcel-mcp/dist/index.js missing; run npm run build first");
  function copyDistJs(fromDir, toDir) {
    for (const name of readdirSync(fromDir).sort()) {
      const source = join(fromDir, name);
      const stat = lstatSync(source);
      if (stat.isSymbolicLink()) fail(`MCP dist must not contain links: ${source}`);
      if (stat.isDirectory()) {
        copyDistJs(source, join(toDir, name));
        continue;
      }
      if (!stat.isFile()) fail(`unsupported MCP dist entry: ${source}`);
      if (!name.endsWith(".js") || name.endsWith(".test.js")) continue;
      mkdirSync(toDir, { recursive: true });
      copyFileSync(source, join(toDir, name));
    }
  }
  copyDistJs(distSource, join(appOut, "dist"));

  const lock = JSON.parse(readFileSync(join(repo, "package-lock.json"), "utf8"));
  const locked = Object.entries(lock.packages ?? {})
    .filter(([key, entry]) => key.startsWith("node_modules/") && !entry.dev && !entry.link)
    .map(([key, entry]) => ({ key, entry }))
    .sort((a, b) => (a.key < b.key ? -1 : 1));
  if (locked.length === 0) fail("package-lock.json lists no production dependencies");
  function copyPackage(from, to) {
    mkdirSync(to, { recursive: true });
    for (const name of readdirSync(from)) {
      if (name === "node_modules" || name === ".bin") continue;
      const source = join(from, name);
      const stat = lstatSync(source);
      if (stat.isSymbolicLink()) fail(`dependency contains a link: ${source}`);
      if (stat.isDirectory()) copyPackage(source, join(to, name));
      else if (stat.isFile()) copyFileSync(source, join(to, name));
    }
  }
  for (const { key, entry } of locked) {
    const source = join(repo, ...key.split("/"));
    const pkgPath = join(source, "package.json");
    if (!existsSync(pkgPath)) fail(`${key} is not installed; run npm ci first`);
    const installed = JSON.parse(readFileSync(pkgPath, "utf8"));
    if (installed.version !== entry.version) {
      fail(`${key} is ${installed.version} but package-lock.json pins ${entry.version}; run npm ci`);
    }
    copyPackage(source, join(appOut, ...key.split("/")));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    console.error("usage: node scripts/mcp-payload.mjs <directory>");
    process.exit(2);
  }
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  stageMcpPayload(repo, resolve(process.argv[2]), (message) => {
    console.error(message);
    process.exit(1);
  });
}
