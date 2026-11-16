// SG-000119 A5: static accessibility checks of the view (the native checks in
// src-tauri/tests/native_qualify.rs read the rendered page and its UI
// Automation tree). Here: the stylesheet uses logical properties only, so the
// layout mirrors under dir="rtl"; every text colour meets WCAG 2.x AA (4.5:1)
// on both backgrounds in the light and the dark scheme, and the focus ring
// 3:1; forced colors are not opted out of; the pages have a language, a
// title, one h1, labelled sections, a polite status line and a named
// scrollable region, and allow zoom; a task's summary is named by what it
// shows (state, kind, identifier, owner, time), never by a title.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import type { TaskSummary } from "./model.js";
import { taskSummaryLabel, taskSummaryNodes } from "./present.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "..", "..", "src-tauri", "ui");
const lf = (text: string) => text.replace(/\r\n/gu, "\n");
const css = lf(readFileSync(path.join(ui, "style.css"), "utf8"));
const declarations = css.replace(/\/\*[\s\S]*?\*\//gu, "");

test("the stylesheet uses no physical left or right property, so dir=rtl mirrors it", () => {
  const physical = [
    /\b(?:margin|padding|border|inset)-(?:left|right)\b/u,
    /\bborder-(?:top|bottom)-(?:left|right)-radius\b/u,
    /(?:^|[\s;{])(?:left|right)\s*:/u,
    /\btext-align\s*:\s*(?:left|right)\b/u,
    /\bfloat\s*:\s*(?:left|right)\b/u,
    /\bclear\s*:\s*(?:left|right)\b/u,
  ];
  for (const pattern of physical) {
    assert.doesNotMatch(declarations, pattern, `a physical property: ${pattern}`);
  }
  // A four-value margin or padding whose right and left differ is physical too.
  for (const match of declarations.matchAll(/\b(margin|padding)\s*:\s*([^;}]+)/gu)) {
    const values = match[2]!.trim().split(/\s+/u);
    if (values.length === 4) {
      assert.equal(values[1], values[3], `${match[0]} sets right and left differently`);
    }
  }
});

/** The custom properties of the first block matching `selectorPattern`. */
function tokens(block: string): Map<string, string> {
  return new Map([...block.matchAll(/--([a-z-]+)\s*:\s*(#[0-9a-f]{6})\s*;/giu)].map((m) => [m[1]!, m[2]!.toLowerCase()]));
}

function light(): Map<string, string> {
  const block = /:root\s*\{([^}]*)\}/u.exec(declarations);
  assert.ok(block, "a :root block");
  return tokens(block[1]!);
}

function dark(): Map<string, string> {
  const block = /@media\s*\(prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([^}]*)\}/u.exec(declarations);
  assert.ok(block, "a dark :root block");
  return tokens(block[1]!);
}

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const value = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

test("contrast: the WCAG formula on known pairs", () => {
  assert.equal(Math.round(contrast("#000000", "#ffffff") * 100) / 100, 21);
  assert.equal(Math.round(contrast("#777777", "#ffffff") * 100) / 100, 4.48);
});

for (const [scheme, read] of [["light", light], ["dark", dark]] as const) {
  test(`every text colour meets 4.5:1 and the focus ring 3:1 in the ${scheme} scheme`, () => {
    const t = read();
    const report: string[] = [];
    for (const background of ["background", "surface"]) {
      for (const text of ["text", "muted", "good", "bad", "withheld"]) {
        const ratio = contrast(t.get(text)!, t.get(background)!);
        report.push(`${text}/${background} ${ratio.toFixed(2)}`);
        assert.ok(ratio >= 4.5, `${scheme} ${text} on ${background}: ${ratio.toFixed(2)}`);
      }
      const focus = contrast(t.get("focus")!, t.get(background)!);
      report.push(`focus/${background} ${focus.toFixed(2)}`);
      assert.ok(focus >= 3, `${scheme} focus on ${background}: ${focus.toFixed(2)}`);
    }
    console.log(`SG119-CONTRAST ${scheme} ${report.join(", ")}`);
  });
}

test("every colour the stylesheet uses is a token checked above (or a system colour in forced colors)", () => {
  const literals = [...declarations.matchAll(/#[0-9a-f]{3,8}\b/giu)].map((m) => m[0].toLowerCase());
  const known = new Set([...light().values(), ...dark().values()]);
  assert.deepEqual(literals.filter((value) => !known.has(value)), []);
  for (const match of declarations.matchAll(/(?:^|[\s;{])(color|background(?:-color)?)\s*:\s*([^;}]+)/gu)) {
    assert.match(match[2]!.trim(), /^(?:var\(--[a-z-]+\)|CanvasText|Canvas|Highlight)$/u, match[0]);
  }
});

test("forced colors: nothing opts out, and focus and borders use system colours", () => {
  assert.doesNotMatch(declarations, /forced-color-adjust/u);
  const block = /@media\s*\(forced-colors:\s*active\)\s*\{([\s\S]*)\}\s*$/u.exec(declarations.trim());
  assert.ok(block, "a forced-colors block at the end");
  assert.match(block[1]!, /:focus-visible\s*\{\s*outline-color:\s*Highlight;/u);
  assert.match(block[1]!, /border-color:\s*CanvasText;/u);
  assert.match(declarations, /:focus-visible\s*\{\s*outline:\s*2px solid var\(--focus\);/u);
});

test("the font size is not fixed below the default and nothing disables zoom", () => {
  for (const page of ["index.html", "start.html"]) {
    const html = lf(readFileSync(path.join(ui, page), "utf8"));
    const viewport = /<meta name="viewport" content="([^"]*)">/u.exec(html);
    assert.ok(viewport, `${page}: a viewport meta`);
    assert.doesNotMatch(viewport[1]!, /user-scalable|maximum-scale|minimum-scale/u, page);
  }
  assert.match(declarations, /font:\s*15px\/1\.5/u);
  assert.doesNotMatch(declarations, /font-size:\s*(?:[0-9.]+px|0\.[0-7][0-9]*(?:rem|em))/u, "no text smaller than 0.8em");
});

test("the pages: language, title, one h1, labelled sections, a polite status line, a named region", () => {
  for (const page of ["index.html", "start.html"]) {
    const html = lf(readFileSync(path.join(ui, page), "utf8"));
    assert.match(html, /<html lang="en">/u, page);
    assert.match(html, /<title>Orcel Control Room<\/title>/u, page);
    assert.equal([...html.matchAll(/<h1\b/gu)].length, 1, page);
    assert.match(html, /role="status"/u, page);
  }
  const html = lf(readFileSync(path.join(ui, "index.html"), "utf8"));
  assert.match(html, /<p id="connection" class="connection" role="status" aria-live="polite">/u);
  const headings = new Map([...html.matchAll(/<h2 id="([a-z-]+)">([^<]+)<\/h2>/gu)].map((m) => [m[1]!, m[2]!]));
  assert.deepEqual([...headings.values()], ["orceld", "Capabilities", "Report tasks", "Live events"]);
  const sections = [...html.matchAll(/<section class="panel" aria-labelledby="([a-z-]+)">/gu)].map((m) => m[1]!);
  assert.deepEqual(sections, [...headings.keys()], "each section is named by its own heading");
  // The only element given a tab stop is the scrollable timeline, so a
  // keyboard can scroll it; it is named apart from its section.
  const stops = [...html.matchAll(/<([a-z]+)[^>]*tabindex="([^"]+)"[^>]*>/gu)];
  assert.equal(stops.length, 1);
  assert.equal(stops[0]![2], "0");
  assert.match(stops[0]![0], /id="timeline-body"/u);
  assert.match(stops[0]![0], /role="region" aria-label="Live events list, scrollable"/u);
});

test("a task's summary is named by what it shows, in reading order, never by a title", () => {
  const summary: TaskSummary & { title?: string } = {
    task_id: "rpt-2ccd856f3d0bd600ff06b6fc39dbc30f",
    workspace_id: "default",
    kind: "report",
    state: "awaiting_check",
    owner: "this_session",
    created_at_ms: { state: "shown", value: 1_763_000_000_000 },
    updated_at_ms: { state: "shown", value: 1_763_000_100_000 },
    title: "Q3 revenue for the board",
  };
  const label = taskSummaryLabel(summary);
  assert.match(label, /^awaiting check, report task rpt-2ccd856f3d0bd600ff06b6fc39dbc30f, owner: this session; updated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/u);
  assert.doesNotMatch(label, /Q3|revenue|board/u);
  // The same words the summary shows, in the same order.
  const shown = taskSummaryNodes(summary).map((node) => node.text ?? "");
  let at = 0;
  for (const part of [shown[0]!, shown[1]!, shown[2]!]) {
    const found = label.indexOf(part, at);
    assert.ok(found >= at, `"${part}" in order in "${label}"`);
    at = found + part.length;
  }
  // Hostile text in a field the label uses is bounded words, not markup.
  assert.match(taskSummaryLabel({ ...summary, state: "<b>x</b>", owner: "a\u202eb" }), /^other, report task .*, owner: other;/u);
});
