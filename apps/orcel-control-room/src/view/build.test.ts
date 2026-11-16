// SG-000119 A4: the shell's built front end (src-tauri/ui, its frontendDist)
// is exactly what tsc compiles from src/view with tsconfig.view.json, and it
// contains no remote URL, no code evaluation, no HTML parsing sink, no inline
// handler or script, no element that acts or navigates, and no call beyond
// the five read-only commands.

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..", "..");
const ui = path.join(packageRoot, "src-tauri", "ui");
const viewSources = path.join(packageRoot, "src", "view");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? files(full) : [full];
  });
}

const lf = (text: string) => text.replace(/\r\n/gu, "\n");
const relative = (file: string) => path.relative(packageRoot, file).split(path.sep).join("/");

test("src-tauri/ui/js is exactly tsc's compile of tsconfig.view.json", () => {
  const configPath = path.join(packageRoot, "tsconfig.view.json");
  const read = ts.readConfigFile(configPath, (file) => ts.sys.readFile(file));
  assert.equal(read.error, undefined);
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, packageRoot, undefined, configPath);
  assert.deepEqual(parsed.errors, []);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const diagnostics = ts.getPreEmitDiagnostics(program).map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
  assert.deepEqual(diagnostics, []);
  const emitted = new Map<string, string>();
  program.emit(undefined, (file, text) => emitted.set(relative(path.resolve(file)), lf(text)));
  const committed = new Map(files(path.join(ui, "js")).map((file) => [relative(file), lf(readFileSync(file, "utf8"))]));
  assert.deepEqual([...committed.keys()].sort(), [...emitted.keys()].sort(), "the same files (run `npm run build:view`)");
  for (const [file, text] of emitted) {
    assert.equal(committed.get(file), text, `${file} differs from tsc's output (run \`npm run build:view\`)`);
  }
});

/** What the built front end and the view's sources must never contain. */
const FORBIDDEN: Array<[RegExp, string]> = [
  [/\b(?:https?|wss?|ftp):\/\//iu, "a remote URL"],
  [/@import|url\s*\(/iu, "a stylesheet import or url()"],
  [/\beval\s*\(/u, "eval"],
  [/\bFunction\s*\(/u, "Function"],
  [/\bnew\s+Function\b/u, "new Function"],
  [/innerHTML|outerHTML/u, "an HTML property sink"],
  [/insertAdjacentHTML|createContextualFragment|DOMParser|srcdoc/u, "an HTML parsing sink"],
  [/document\s*\.\s*write/u, "document.write"],
  [/\bset(?:Timeout|Interval)\s*\(\s*["'`]/u, "a string timer"],
  [/\bimport\s*\(/u, "a dynamic import"],
  [/javascript:/iu, "a javascript: URL"],
  [/\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon/u, "a network call of its own"],
  [/\blocalStorage\b|\bsessionStorage\b|indexedDB/u, "browser storage"],
  [/window\s*\.\s*open\s*\(|location\s*\.\s*(?:href|assign|replace)/u, "navigation or a new window"],
  [/\.postMessage\s*\(/u, "a web message"],
];

const SHIPPED = () => files(ui);

test("the built front end has no remote URL, no eval, no HTML sink and no network or navigation call", () => {
  const hits: string[] = [];
  for (const file of [...SHIPPED(), ...files(viewSources).filter((f) => !f.endsWith(".test.ts"))]) {
    readFileSync(file, "utf8")
      .split(/\r?\n/u)
      .forEach((line, index) => {
        for (const [pattern, what] of FORBIDDEN) {
          if (pattern.test(line)) hits.push(`${relative(file)}:${index + 1}: ${what}: ${line.trim()}`);
        }
      });
  }
  assert.deepEqual(hits, []);
});

test("the pages and the stylesheet name no protocol-relative URL", () => {
  for (const file of SHIPPED().filter((f) => /\.(?:html|css)$/u.test(f))) {
    assert.ok(!/["'(=]\s*\/\//u.test(readFileSync(file, "utf8")), relative(file));
  }
});

test("the pages: one external module script on the view, none on the start page, no inline handler or acting element", () => {
  const index = readFileSync(path.join(ui, "index.html"), "utf8");
  const start = readFileSync(path.join(ui, "start.html"), "utf8");
  const scripts = [...index.matchAll(/<script\b[^>]*>/giu)].map((match) => match[0]);
  assert.deepEqual(scripts, ['<script type="module" src="js/view/main.js">']);
  assert.match(index, /<script type="module" src="js\/view\/main\.js"><\/script>/u, "the script has no inline body");
  assert.ok(!/<script\b/iu.test(start), "the page shown before hardening runs no script");
  for (const page of [index, start]) {
    assert.ok(!/\son[a-z]+\s*=/iu.test(page), "no inline event handler");
    assert.ok(!/\sstyle\s*=/iu.test(page), "no inline style");
    assert.ok(!/<(?:a|button|input|form|select|textarea|img|iframe|object|embed|base|meta\s+http-equiv)\b/iu.test(page), "no element that acts, navigates or loads");
    const links = [...page.matchAll(/<link\b[^>]*>/giu)].map((match) => match[0]);
    assert.deepEqual(links, ['<link rel="stylesheet" href="style.css">']);
  }
});

test("only the view's own modules and the headless reducer load; none reaches for Node", () => {
  const seen = new Set<string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    const text = readFileSync(path.join(ui, file), "utf8");
    for (const match of text.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+"([^"]+)";/gmu)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), match[1] as string));
      assert.ok(match[1]?.startsWith("."), `${file} imports ${match[1]} (only relative modules)`);
      visit(target);
    }
  };
  visit("js/view/main.js");
  assert.deepEqual([...seen].sort(), [
    "js/agentkit/client/state.js",
    "js/agentkit/protocol/errors.js",
    "js/view/dom.js",
    "js/view/main.js",
    "js/view/model.js",
    "js/view/present.js",
    "js/view/timeline.js",
  ]);
  for (const file of seen) {
    const text = readFileSync(path.join(ui, file), "utf8");
    assert.ok(!/\bBuffer\b|\bprocess\.|\brequire\s*\(|["']node:/u.test(text), `${file} uses a Node API`);
  }
});

test("the page calls exactly the five read-only commands and nothing that acts", () => {
  const main = readFileSync(path.join(viewSources, "main.ts"), "utf8");
  const commands = new Set([...main.matchAll(/\b(?:read(?:<[^>]*>)?|invoke)\(\s*"([^"]+)"/gu)].map((match) => match[1]));
  assert.deepEqual([...commands].sort(), ["app_capabilities", "app_events", "app_status", "app_task", "app_tasks"]);
  assert.equal([...main.matchAll(/\.invoke\(/gu)].length, 2, "one generic read and the subscription");
  const sources = files(viewSources).filter((file) => !file.endsWith(".test.ts"));
  for (const file of sources) {
    const text = readFileSync(file, "utf8");
    assert.ok(!/task[._]stop|approval\.[a-z]|approval_history|clients[._]list|devices_list|app_api_call/u.test(text), `${relative(file)} names a method outside the five`);
    assert.ok(!/\b(?:approve|deny|grant|dismiss|answer|cancel|submit|stop)[A-Z]\w*\s*\(/u.test(text), `${relative(file)} defines an acting function`);
    assert.ok(!/(?:pending|waiting for|awaiting)\s+approval/iu.test(text), `${relative(file)} describes a pending approval`);
    assert.ok(!/addEventListener\(\s*"(?:click|keydown|keyup|keypress|submit|contextmenu)"/u.test(text), `${relative(file)} handles an input event`);
  }
});
