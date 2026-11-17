import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BROWSER_FULL_TOOLS, LIVE_BROWSER_TOOLS } from "./tool_contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

function toolSources(): string[] {
  return readdirSync(srcDir).filter(
    (name) => name.endsWith(".ts") && !name.endsWith(".test.ts")
  );
}

test("no MCP tool source forwards a browser capability to the kernel", () => {
  const offenders: string[] = [];
  for (const name of toolSources()) {
    const text = readFileSync(join(srcDir, name), "utf8");
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      // SG-000108: the governed exposure tables in tool_contract.ts name
      // the live browser tools and their shapes; browser_live.ts registers
      // them and forwards each one's contract shape without naming any
      // (browser-exposure.test.ts ties both to orceld and the host). No other
      // file may name a browser capability or register one.
      const table =
        name === "tool_contract.ts" &&
        (/LIVE_BROWSER_TOOLS|SG-000108 slice 3c/.test(line) || /^\s*(?:"browser_[a-z_]+",?|browser_[a-z_]+: \{)\s*$/.test(line) || /capability: "browser\./.test(line));
      if (
        (!table && /(["'])browser\./.test(line)) ||
        /registerBrowser/i.test(line) ||
        (!table && /browser[-_]tools?/i.test(line))
      ) {
        offenders.push(`${name}:${String(index + 1)}:${line.trim()}`);
      }
    });
  }
  assert.deepEqual(offenders, []);
  // browser_live.ts forwards exactly the live tools' shapes, and only them.
  const live = readFileSync(join(srcDir, "browser_live.ts"), "utf8");
  const registered = [...live.matchAll(/registerTool\(\s*"([^"]+)"/g)].map((match) => match[1]).sort();
  assert.deepEqual(registered, [...LIVE_BROWSER_TOOLS].sort());
  const code = live
    .split("\n")
    .filter((line) => !/^\s*(\*|\/\/|\/\*)/.test(line))
    .join("\n");
  assert.doesNotMatch(code, /evaluate|newCDPSession|devtools|selector|coordinate|execute_script/i);
  // SG-000135 OB-02: browser_full.ts registers exactly the broker tools, by
  // their contract shapes, under the same rules.
  const full = readFileSync(join(srcDir, "browser_full.ts"), "utf8");
  const brokered = [...full.matchAll(/registerTool\(\s*"([^"]+)"/g)].map((match) => match[1]).sort();
  assert.deepEqual(brokered, [...BROWSER_FULL_TOOLS].sort());
  const fullCode = full
    .split("\n")
    .filter((line) => !/^\s*(\*|\/\/|\/\*)/.test(line))
    .join("\n");
  assert.doesNotMatch(fullCode, /evaluate|newCDPSession|devtools|selector|coordinate|execute_script|capability: "/i);
});

test("no browser tool is registered on the MCP server surface", () => {
  const text = readFileSync(join(srcDir, "server.ts"), "utf8");
  assert.match(text, /registerGitFetchTools/);
  // SG-000108: server.ts names the `browser_structured` profile (selected
  // by local configuration) and hands registration to browser_live.ts; it
  // registers and forwards no browser tool or capability itself.
  // SG-000135 OB-02: likewise the `browser_full` profile, whose broker tools
  // browser_full.ts registers (browser-full.test.ts ties them to orceld and
  // the host).
  const withoutGoverned = text
    .replace(/`?browser_structured`?/g, "")
    .replace(/"?`?browser_full`?"?/g, "")
    .replace(/import \{ registerLiveBrowserTools \} from "\.\/browser_live\.js";/g, "")
    .replace(/import \{ registerSessionBrokerTools \} from "\.\/browser_full\.js";/g, "")
    .replace(/registerLiveBrowserTools\(server, kernel, defaultWorkspace\);/g, "")
    .replace(/registerSessionBrokerTools\(server, kernel, defaultWorkspace\);/g, "")
    // The catalog names the live tools (SG-000108 slice 3c, SG-000122 slices A3 and A4).
    .replace(/"browser_(check|click|download|download_preview|enter|fill|navigate|observe|page_open|select|verify|wait_text)",/g, "");
  assert.doesNotMatch(withoutGoverned, /browser/i);
});
