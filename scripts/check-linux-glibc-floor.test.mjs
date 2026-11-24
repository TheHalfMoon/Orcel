import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  BINARIES,
  checkDist,
  checkElf,
  checkTree,
  compareVersions,
  GLIBC_FLOOR,
  glibcRelease,
  judge,
  requiredVersions,
  symbolsRequiring,
} from "./check-linux-glibc-floor.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(REPO, path), "utf8").replaceAll("\r\n", "\n");

// CI sets this so that a missing readelf fails instead of skipping.
const hasReadelf = spawnSync("readelf", ["--version"]).status === 0;
const needsReadelf = { skip: !hasReadelf && !process.env.ORCEL_REQUIRE_READELF && "no readelf here" };

/** A minimal x86-64 ELF shared object whose version needs are `needs`: [[file, [[name, flags], ...]], ...]. */
function elf(needs) {
  const strings = [Buffer.from("\0")];
  const string = (text) => {
    const at = strings.reduce((length, part) => length + part.length, 0);
    strings.push(Buffer.from(`${text}\0`));
    return at;
  };
  const verneed = [];
  const symbols = [Buffer.alloc(24)];
  const versions = [0];
  let index = 2;
  needs.forEach(([file, names], position) => {
    const header = Buffer.alloc(16);
    header.writeUInt16LE(1, 0);
    header.writeUInt16LE(names.length, 2);
    header.writeUInt32LE(string(file), 4);
    header.writeUInt32LE(16, 8);
    header.writeUInt32LE(position === needs.length - 1 ? 0 : 16 + 16 * names.length, 12);
    verneed.push(header);
    names.forEach(([name, flags], at) => {
      const aux = Buffer.alloc(16);
      aux.writeUInt16LE(flags, 4);
      aux.writeUInt16LE(index, 6);
      aux.writeUInt32LE(string(name), 8);
      aux.writeUInt32LE(at === names.length - 1 ? 0 : 16, 12);
      verneed.push(aux);
      const symbol = Buffer.alloc(24);
      symbol.writeUInt32LE(string(`uses_${name}`), 0);
      symbol[4] = 0x12;
      symbols.push(symbol);
      versions.push(index);
      index += 1;
    });
  });
  const names = "\0.dynstr\0.gnu.version_r\0.dynsym\0.gnu.version\0.shstrtab\0";
  const sections = [
    [".dynstr", 3, Buffer.concat(strings), 0, 0, 0],
    [".gnu.version_r", 0x6ffffffe, Buffer.concat(verneed), 1, needs.length, 0],
    [".dynsym", 11, Buffer.concat(symbols), 1, 1, 24],
    [".gnu.version", 0x6fffffff, Buffer.from(new Uint16Array(versions).buffer), 3, 0, 2],
    [".shstrtab", 3, Buffer.from(names), 0, 0, 0],
  ].filter(([name]) => needs.length > 0 || !name.startsWith(".gnu.version"));
  const header = Buffer.alloc(64);
  header.write("\x7fELF\x02\x01\x01", 0, "latin1");
  header.writeUInt16LE(3, 16);
  header.writeUInt16LE(62, 18);
  header.writeUInt32LE(1, 20);
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(64, 58);
  header.writeUInt16LE(sections.length + 1, 60);
  header.writeUInt16LE(sections.length, 62);
  const body = [];
  const table = [Buffer.alloc(64)];
  let offset = 64;
  for (const [name, type, data, link, info, entry] of sections) {
    const section = Buffer.alloc(64);
    section.writeUInt32LE(names.indexOf(name), 0);
    section.writeUInt32LE(type, 4);
    section.writeBigUInt64LE(2n, 8);
    section.writeBigUInt64LE(BigInt(offset), 16);
    section.writeBigUInt64LE(BigInt(offset), 24);
    section.writeBigUInt64LE(BigInt(data.length), 32);
    section.writeUInt32LE(link, 40);
    section.writeUInt32LE(info, 44);
    section.writeBigUInt64LE(8n, 48);
    section.writeBigUInt64LE(BigInt(entry), 56);
    table.push(section);
    const padded = Buffer.concat([data, Buffer.alloc((8 - (data.length % 8)) % 8)]);
    body.push(padded);
    offset += padded.length;
  }
  header.writeBigUInt64LE(BigInt(offset), 40);
  return Buffer.concat([header, ...body, ...table]);
}

const OK = [
  ["libgcc_s.so.1", [["GCC_3.0", 0]]],
  ["libc.so.6", [["GLIBC_2.2.5", 0], ["GLIBC_2.39", 2], ["GLIBC_ABI_DT_RELR", 0]]],
];

function withTree(files, use) {
  const root = mkdtempSync(join(tmpdir(), "orcel-glibc-floor-test-"));
  try {
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), content);
    }
    return use(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const tree = (overrides = {}) => ({
  ...Object.fromEntries(BINARIES.map((name) => [`usr/lib/orcel/${name}`, elf(OK)])),
  "usr/share/doc/orcel/README.md": "not an ELF file",
  ...overrides,
});

test("versions compare by number, not as text", () => {
  assert.equal(compareVersions("2.9", "2.39"), -1);
  assert.equal(compareVersions("2.2.5", "2.2"), 1);
  assert.equal(compareVersions("2.40", "2.39"), 1);
  assert.equal(compareVersions("3.0", "2.39"), 1);
  assert.equal(compareVersions("2.39", "2.39"), 0);
});

test("only names the gate can rank have a release", () => {
  assert.equal(glibcRelease("GLIBC_2.2.5"), "2.2.5");
  assert.equal(glibcRelease("GLIBC_ABI_DT_RELR"), "2.36");
  for (const name of ["GLIBC_PRIVATE", "GLIBC_ABI_GNU2_TLS", "GLIBC_2", "GLIBC_2.x", "GLIBC_"]) {
    assert.equal(glibcRelease(name), null, name);
  }
});

test("a requirement above the floor, an unrankable one, or none at all is a problem", () => {
  assert.deepEqual(judge(["GCC_4.2.0", "GLIBC_2.2.5", "GLIBC_2.39"]).problems, []);
  assert.equal(judge(["GLIBC_2.2.5", "GLIBC_2.39"]).highest, "2.39");
  const above = judge(["GLIBC_2.39", "GLIBC_2.43", "GLIBC_2.40"]);
  assert.deepEqual(above.above, ["GLIBC_2.40", "GLIBC_2.43"]);
  assert.match(above.problems.join(), /GLIBC_2\.40, GLIBC_2\.43, newer than the documented floor glibc 2\.39/);
  assert.match(judge(["GLIBC_PRIVATE", "GLIBC_2.2.5"]).problems.join(), /GLIBC_PRIVATE/);
  assert.match(judge(["GCC_3.0"]).problems.join(), /no GLIBC_ requirement/);
  assert.match(judge([]).problems.join(), /no GLIBC_ requirement/);
});

test("only the needs section counts, and a listing that does not add up is refused", () => {
  const listing = [
    "Version definition section '.gnu.version_d' contains 1 entry:",
    "  0x001c:   Name: GLIBC_9.9  Flags: none  Version: 2",
    "",
    "Version needs section '.gnu.version_r' contains 1 entry:",
    " Addr: 0x0000000000001000  Offset: 0x00001000  Link: 6 (.dynstr)",
    "  000000: Version: 1  File: libc.so.6  Cnt: 2",
    "  0x0010:   Name: GLIBC_2.39  Flags: WEAK  Version: 3",
    "  0x0020:   Name: GLIBC_2.2.5  Flags: none  Version: 2",
    "",
  ];
  assert.deepEqual(requiredVersions(listing.join("\n")), ["GLIBC_2.39", "GLIBC_2.2.5"]);
  assert.throws(() => requiredVersions(listing.toSpliced(6, 1).join("\n")), /announced 2 .* listed 1/);
  assert.throws(() => requiredVersions(listing.toSpliced(5, 1).join("\n")), /announced 0 .* listed 2/);
  assert.deepEqual(requiredVersions("\nNo version information found in this file.\n"), []);
});

test("the failure names the symbols that need the newer glibc", () => {
  const listing = [
    "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)",
    "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND newer@GLIBC_2.43 (4)",
    "     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND other@GLIBC_2.4 (5)",
  ].join("\n");
  assert.deepEqual(symbolsRequiring(listing, ["GLIBC_2.43"]), ["newer@GLIBC_2.43"]);
});

test("the real readelf: a package at the floor passes, one symbol above it fails by name", needsReadelf, () => {
  const good = withTree(tree(), (root) => checkTree(root, "good.deb"));
  assert.deepEqual(good.errors, []);
  assert.equal(good.report.length, BINARIES.length);
  assert.ok(good.report.every((line) => line.includes("highest glibc requirement 2.39, floor 2.39")), good.report);

  const newer = elf([["libc.so.6", [["GLIBC_2.2.5", 0], ["GLIBC_2.43", 0]]]]);
  const bad = withTree(tree({ "usr/lib/orcel/orceld": newer }), (root) => checkTree(root, "bad.deb"));
  assert.match(bad.errors[0], /^bad\.deb: usr\/lib\/orcel\/orceld: requires GLIBC_2\.43, newer than/);
  assert.ok(bad.errors.every((error) => error.startsWith("bad.deb: usr/lib/orcel/orceld: ")), bad.errors.join("\n"));

  const weak = elf([["libc.so.6", [["GLIBC_2.2.5", 0], ["GLIBC_2.41", 2]]]]);
  const extra = withTree(tree({ "opt/extra": weak }), (root) => checkTree(root, "x.deb"));
  assert.match(extra.errors.join("\n"), /opt\/extra: requires GLIBC_2\.41/, "every ELF file counts, weak too");

  withTree({ f: elf([["libc.so.6", [["GLIBC_2.39", 0]]]]) }, (root) =>
    assert.match(checkElf(join(root, "f"), "2.38").problems.join(), /GLIBC_2\.39/));
});

test("the real readelf: a missing binary, no version list and a broken ELF file fail", needsReadelf, () => {
  const files = tree();
  delete files["usr/lib/orcel/orcel-contain"];
  const missing = withTree(files, (root) => checkTree(root, "x.deb"));
  assert.deepEqual(missing.errors, ["x.deb: does not hold exactly one ELF file named orcel-contain"]);

  const none = withTree(tree({ "usr/lib/orcel/orceld": elf([]) }), (root) => checkTree(root, "x.deb"));
  assert.match(none.errors.join("\n"), /orceld: no GLIBC_ requirement found/);

  const broken = withTree(tree({ "usr/lib/orcel/orceld": "\x7fELF" }), (root) => checkTree(root, "x.deb"));
  assert.match(broken.errors.join("\n"), /usr\/lib\/orcel\/orceld: /);
});

test("a directory without the three packages fails", () => {
  const { errors } = withTree({ "a.txt": "" }, (root) => checkDist(root));
  assert.equal(errors.length, 3);
  for (const suffix of [".deb", ".rpm", ".tar.gz"]) {
    assert.ok(errors.some((error) => error.includes(`exactly one *${suffix}, found 0`)), errors.join("\n"));
  }
});

/** The lines of one job, without comment lines. */
function job(workflow, name) {
  const lines = read(`.github/workflows/${workflow}`).split("\n");
  const start = lines.indexOf(`  ${name}:`);
  assert.ok(start >= 0, `${workflow} has the job ${name}`);
  const length = lines.slice(start + 1).findIndex((line) => /^ {2}[A-Za-z]/.test(line));
  return lines.slice(start, length < 0 ? undefined : start + 1 + length).filter((line) => !/^\s*#/.test(line));
}

test("both package builds run on ubuntu-24.04 and check the packages before anything uses them", () => {
  for (const [workflow, name] of [["ci.yml", "linux-packages"], ["release.yml", "build-linux"]]) {
    const lines = job(workflow, name);
    assert.deepEqual(
      lines.filter((line) => /^ {4}runs-on:/.test(line)),
      ["    runs-on: ubuntu-24.04"],
      `${workflow}: the build runner is pinned, so its glibc does not move`,
    );
    const text = lines.join("\n");
    assert.ok(!text.includes("continue-on-error"), `${workflow}: no step may fail quietly`);
    const at = (needle) => {
      assert.equal(text.split(needle).length - 1, 1, `${workflow}: ${needle} appears once`);
      return text.indexOf(needle);
    };
    const packaged = at("bash distribution/linux/package.sh ");
    const floor = at("node scripts/check-linux-glibc-floor.mjs ");
    const smoke = at("bash distribution/linux/smoke-ubuntu.sh ");
    assert.ok(packaged < floor && floor < smoke, `${workflow}: build, then floor, then smoke test`);
    if (workflow === "release.yml") assert.ok(smoke < at("actions/upload-artifact@"), "checked before the upload");
  }
});

test("the documented floor is the one the gate enforces, and containers are pinned by digest", () => {
  assert.equal(GLIBC_FLOOR, "2.39");
  const readme = read("distribution/linux/README.md");
  assert.ok(readme.includes(`glibc ${GLIBC_FLOOR}`), "README.md names the floor");
  assert.ok(readme.includes("### deb (Ubuntu 24.04 and later) or rpm (Fedora 41 and later)"));
  assert.match(
    read("distribution/linux/smoke-ubuntu.sh"),
    /^image=docker\.io\/library\/ubuntu@sha256:[0-9a-f]{64}$/m,
  );
  assert.match(job("ci.yml", "linux-packages").join("\n"), /docker\.io\/library\/fedora@sha256:[0-9a-f]{64} /);
});
