// Runs in the linux-packages job, after packaging, with ORCEL_LINUX_DIST
// naming the directory of the deb, rpm and tarball that job built: the real
// dpkg-deb, bsdtar, rpm, tar and readelf on the real packages. Elsewhere the
// tests that need a missing program or the packages skip; with
// ORCEL_LINUX_DIST set nothing skips.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { BINARIES, checkDist, checkTree, rpmProblems, SYSTEM } from "./check-linux-glibc-floor.mjs";

const GATE = resolve(dirname(fileURLToPath(import.meta.url)), "check-linux-glibc-floor.mjs");
const DIST = process.env.ORCEL_LINUX_DIST;
const needsDist = { skip: !DIST && "ORCEL_LINUX_DIST is not set" };
const needsReadelf = { skip: !DIST && spawnSync("readelf", ["--version"]).status !== 0 && "no readelf here" };

/** A minimal x86-64 ELF shared object whose version needs are `needs`: [[file, [[name, flags], ...]], ...]. */
function elf(needs) {
  const strings = [Buffer.from("\0")];
  const string = (text) => {
    const at = strings.reduce((length, part) => length + part.length, 0);
    strings.push(Buffer.from(`${text}\0`));
    return at;
  };
  const verneed = [];
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
      index += 1;
    });
  });
  const names = "\0.dynstr\0.gnu.version_r\0.shstrtab\0";
  const sections = [
    [".dynstr", 3, Buffer.concat(strings), 0, 0],
    [".gnu.version_r", 0x6ffffffe, Buffer.concat(verneed), 1, needs.length],
    [".shstrtab", 3, Buffer.from(names), 0, 0],
  ].filter(([name]) => needs.length > 0 || name !== ".gnu.version_r");
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
  for (const [name, type, data, link, info] of sections) {
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
    table.push(section);
    const padded = Buffer.concat([data, Buffer.alloc((8 - (data.length % 8)) % 8)]);
    body.push(padded);
    offset += padded.length;
  }
  header.writeBigUInt64LE(BigInt(offset), 40);
  return Buffer.concat([header, ...body, ...table]);
}

const NEWER = elf([["libc.so.6", [["GLIBC_2.2.5", 0], ["GLIBC_2.40", 2]]]]);

function withDir(use) {
  const root = mkdtempSync(join(tmpdir(), "orcel-glibc-floor-linux-"));
  try {
    return use(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const only = (dist, suffix) => {
  const found = readdirSync(dist).filter((name) => name.endsWith(suffix));
  assert.equal(found.length, 1, `one *${suffix}`);
  return join(dist, found[0]);
};

/** Judges a copy of the built packages after `change`, through the command line. */
function cli(change) {
  return withDir((root) => {
    cpSync(DIST, root, { recursive: true });
    change(root);
    return spawnSync(process.execPath, [GATE, root], { encoding: "utf8" });
  });
}

const maxima = (done) => done.stdout.match(/: highest glibc requirement \d\S*, floor 2\.39$/gm)?.length ?? 0;

test("the real readelf reads a version list, and refuses an ELF file without one", needsReadelf, () => {
  const judgeOne = (content) =>
    withDir((root) => {
      for (const name of BINARIES) writeFileSync(join(root, name), content);
      return checkTree(root, "x");
    });
  const ok = elf([
    ["libgcc_s.so.1", [["GCC_3.0", 0]]],
    ["libc.so.6", [["GLIBC_2.2.5", 0], ["GLIBC_2.39", 2], ["GLIBC_ABI_DT_RELR", 0]]],
  ]);
  const good = judgeOne(ok);
  assert.deepEqual(good.errors, []);
  assert.ok(good.report.every((line) => line.endsWith("highest glibc requirement 2.39, floor 2.39")), good.report.join("\n"));
  assert.match(judgeOne(NEWER).errors.join("\n"), /orceld: requires GLIBC_2\.40, newer than/, "weak requirements count");
  assert.match(judgeOne(elf([])).errors.join("\n"), /orceld: no GLIBC_ requirement found/);
  assert.equal(judgeOne("\x7fELF").errors.length, BINARIES.length);
});

test("the built packages pass, with every binary's maximum printed", needsDist, () => {
  const done = cli(() => {});
  assert.equal(done.status, 0, done.stderr);
  assert.equal(maxima(done), 9, done.stdout);
  assert.match(done.stdout, /Every packaged ELF file requires glibc 2\.39 or older\.\n$/);
});

test("the gate reads the built binaries: a floor below them refuses all nine", needsDist, () => {
  const { errors } = checkDist(DIST, SYSTEM, "2.2");
  assert.equal(errors.filter((error) => error.includes("newer than the documented floor glibc 2.2")).length, 9);
  assert.ok(errors.some((error) => /symbols: \S+@GLIBC_/.test(error)), "and names symbols");
});

test("the built rpm unpacks to exactly its header's files; a lost, changed or extra file is seen", needsDist, () => {
  withDir((root) => {
    const rpm = only(DIST, ".rpm");
    const dump = SYSTEM.rpmDump(rpm);
    SYSTEM.unpack(".rpm", rpm, root);
    assert.deepEqual(rpmProblems(dump, root), []);
    for (const path of [...BINARIES, "orcel-contain.sha256"]) assert.ok(existsSync(join(root, "usr/lib/orcel", path)), path);
    const orceld = join(root, "usr/lib/orcel/orceld");
    const bytes = readFileSync(orceld);
    const changed = Buffer.from(bytes);
    changed[bytes.length - 1] ^= 0xff;
    writeFileSync(orceld, changed);
    assert.match(rpmProblems(dump, root).join(), /orceld was unpacked with other bytes/);
    rmSync(orceld);
    assert.match(rpmProblems(dump, root).join(), /orceld was not unpacked/);
    writeFileSync(orceld, bytes);
    writeFileSync(join(root, "extra"), "");
    assert.deepEqual(rpmProblems(dump, root), ["/extra was unpacked but the header does not list it"]);
  });
});

test("a cut or damaged rpm fails, and the other packages are still judged", needsDist, () => {
  for (const damage of [
    (bytes) => bytes.subarray(0, Math.floor(bytes.length * 0.6)),
    (bytes) => {
      const copy = Buffer.from(bytes);
      copy[Math.floor(copy.length * 0.6)] ^= 0xff;
      return copy;
    },
  ]) {
    const done = cli((root) => {
      const rpm = only(root, ".rpm");
      writeFileSync(rpm, damage(readFileSync(rpm)));
    });
    assert.equal(done.status, 1);
    assert.match(done.stderr, /^glibc floor: \S+\.rpm: /m);
    assert.ok(maxima(done) >= 6, done.stdout);
  }
});

test("a real tarball with one newer binary fails by name", needsDist, () => {
  const done = cli((root) => {
    const tarball = only(root, ".tar.gz");
    const tree = join(root, "tree");
    mkdirSync(tree);
    SYSTEM.unpack(".tar.gz", tarball, tree);
    const [name] = readdirSync(tree);
    writeFileSync(join(tree, name, "bin/orceld"), NEWER);
    const packed = spawnSync("tar", ["-C", tree, "-czf", tarball, name], { encoding: "utf8" });
    assert.equal(packed.status, 0, packed.stderr);
    rmSync(tree, { recursive: true });
  });
  assert.equal(done.status, 1);
  assert.match(done.stderr, /\.tar\.gz: \S+\/bin\/orceld: requires GLIBC_2\.40, newer than the documented floor glibc 2\.39/);
  assert.match(done.stderr, /the packages hold 2 different builds of orceld/);
  assert.equal(maxima(done), 9, done.stdout);
});
