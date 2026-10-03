import { describe, expect, it } from "vitest";

import {
  normalizeEsmImportSpecifier,
  normalizeGeneratedEsmImportSpecifiers,
  stringifyEsmImportSpecifier,
} from "./import-specifier.js";

describe("normalizeEsmImportSpecifier", () => {
  it("converts Windows drive-letter paths to file URLs", () => {
    expect(
      normalizeEsmImportSpecifier("G:\\projects\\test orcel\\node_modules\\pkg\\dist\\route.js"),
    ).toBe("file:///G:/projects/test%20orcel/node_modules/pkg/dist/route.js");
    expect(normalizeEsmImportSpecifier("G:/projects/test-orcel/route.js")).toBe(
      "file:///G:/projects/test-orcel/route.js",
    );
    expect(normalizeEsmImportSpecifier("/G:/projects/test-orcel/route.js")).toBe(
      "file:///G:/projects/test-orcel/route.js",
    );
    expect(normalizeEsmImportSpecifier("G:\\projects\\test-orcel\\route.js?meta")).toBe(
      "file:///G:/projects/test-orcel/route.js?meta",
    );
  });

  it("converts Windows UNC paths to file URLs", () => {
    expect(normalizeEsmImportSpecifier("\\\\server\\share\\test orcel\\route.js")).toBe(
      "file://server/share/test%20orcel/route.js",
    );
  });

  it("leaves POSIX absolute paths as path specifiers", () => {
    expect(normalizeEsmImportSpecifier("/tmp/test orcel/route.js")).toBe("/tmp/test orcel/route.js");
  });

  it("leaves existing file URLs and package specifiers intact", () => {
    expect(normalizeEsmImportSpecifier("file:///G:/projects/test-orcel/route.js")).toBe(
      "file:///G:/projects/test-orcel/route.js",
    );
    expect(normalizeEsmImportSpecifier("workflow/api")).toBe("workflow/api");
  });

  it("normalizes relative specifier separators", () => {
    expect(normalizeEsmImportSpecifier(".\\routes\\handler.js")).toBe("./routes/handler.js");
  });
});

describe("stringifyEsmImportSpecifier", () => {
  it("serializes normalized specifiers for generated source", () => {
    expect(stringifyEsmImportSpecifier("G:\\projects\\test-orcel\\route.js")).toBe(
      JSON.stringify("file:///G:/projects/test-orcel/route.js"),
    );
  });
});

describe("normalizeGeneratedEsmImportSpecifiers", () => {
  it("rewrites raw Windows paths in generated ESM imports", () => {
    expect(
      normalizeGeneratedEsmImportSpecifiers(
        [
          'import handler from "G:\\projects\\test-orcel\\route.js";',
          'import "G:\\projects\\test-orcel\\side-effect.js";',
          'const lazy = () => import("G:\\projects\\test-orcel\\lazy.js?meta");',
          "",
        ].join("\n"),
      ),
    ).toBe(
      [
        'import handler from "file:///G:/projects/test-orcel/route.js";',
        'import "file:///G:/projects/test-orcel/side-effect.js";',
        'const lazy = () => import("file:///G:/projects/test-orcel/lazy.js?meta");',
        "",
      ].join("\n"),
    );
  });
});
