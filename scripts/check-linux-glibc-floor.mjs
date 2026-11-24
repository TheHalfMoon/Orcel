#!/usr/bin/env node
// Linux package gate: no ELF file in the deb, the rpm or the per-user tarball
// may require a glibc newer than the documented floor (distribution/linux/
// README.md: Ubuntu 24.04 and later, Fedora 41 and later).
//
// Every requirement `readelf -V` lists counts, weak ones included: a weak
// requirement would still load on an older glibc, but whatever needs it is
// untested there. Anything the gate cannot read or rank fails: a missing
// package, a missing binary, an ELF file with no GLIBC_ requirement, a
// version list that does not add up, or a GLIBC_ name it does not know.
//
// Usage (Linux; needs dpkg-deb, rpm2cpio, cpio, tar and readelf):
//   node scripts/check-linux-glibc-floor.mjs <dist-dir>

import { spawnSync } from "node:child_process";
import { closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, readSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The oldest glibc the packages support: Ubuntu 24.04's. Fedora 41 has 2.40. */
export const GLIBC_FLOOR = "2.39";

/** The binaries every package must hold. */
export const BINARIES = ["orcel-approval-helper-linux", "orcel-contain", "orceld"];

/** Loader features glibc names without a number, with the release that added them. */
const FEATURES = new Map([["GLIBC_ABI_DT_RELR", "2.36"]]);

export function compareVersions(a, b) {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const difference = (left[i] ?? 0) - (right[i] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

/** The glibc release a required version name needs, or null when it cannot be ranked. */
export function glibcRelease(name) {
  if (FEATURES.has(name)) return FEATURES.get(name);
  return /^GLIBC_(\d+(?:\.\d+)+)$/.exec(name)?.[1] ?? null;
}

/** Every version name a `readelf -W -V` listing says the file requires. Throws when it does not add up. */
export function requiredVersions(listing) {
  const names = [];
  let inNeeds = false;
  let expected = 0;
  for (const line of listing.split(/\r?\n/)) {
    if (/^\S/.test(line)) inNeeds = line.startsWith("Version needs section ");
    if (!inNeeds) continue;
    const file = /^\s+(?:0x)?[0-9a-f]+: Version: \d+\s+File: \S+\s+Cnt: (\d+)\s*$/.exec(line);
    if (file) {
      expected += Number(file[1]);
      continue;
    }
    const version = /^\s+(?:0x)?[0-9a-f]+:\s+Name: (\S+)\s+Flags: .+\s+Version: \d+\s*$/.exec(line);
    if (version) names.push(version[1]);
  }
  if (names.length !== expected) {
    throw new Error(`readelf announced ${expected} required versions and listed ${names.length}`);
  }
  return names;
}

/** What is wrong with one file's required versions, and its highest glibc requirement. */
export function judge(names, floor = GLIBC_FLOOR) {
  const problems = [];
  const above = [];
  let highest = null;
  const glibc = names.filter((name) => name.startsWith("GLIBC_"));
  if (glibc.length === 0) problems.push("no GLIBC_ requirement found, so its glibc floor is unknown");
  for (const name of new Set(glibc)) {
    const release = glibcRelease(name);
    if (release === null) {
      problems.push(`requires ${name}, which this gate cannot rank`);
      continue;
    }
    if (highest === null || compareVersions(release, highest) > 0) highest = release;
    if (compareVersions(release, floor) > 0) above.push(name);
  }
  if (above.length > 0) {
    problems.push(`requires ${above.sort().join(", ")}, newer than the documented floor glibc ${floor}`);
  }
  return { highest, above, problems };
}

function run(command, args, options = {}) {
  const done = spawnSync(command, args, {
    maxBuffer: 1 << 30,
    ...options,
    env: { ...process.env, LC_ALL: "C" },
  });
  if (done.error) throw new Error(`${command}: ${done.error.message}`);
  if (done.status !== 0) throw new Error(`${command} exited ${done.status ?? done.signal}: ${done.stderr}`);
  return done.stdout;
}

/** The symbols of a `readelf -W --dyn-syms` listing that carry one of `versions`, for the failure message. */
export function symbolsRequiring(listing, versions) {
  const symbols = listing.match(/\S+@GLIBC_\S+/g) ?? [];
  return symbols.filter((symbol) => versions.some((version) => symbol.endsWith(`@${version}`)));
}

/** Judges one ELF file with the system's readelf. */
export function checkElf(path, floor = GLIBC_FLOOR) {
  const result = judge(requiredVersions(run("readelf", ["-W", "-V", path]).toString()), floor);
  if (result.above.length > 0) {
    const symbols = symbolsRequiring(run("readelf", ["-W", "--dyn-syms", path]).toString(), result.above);
    if (symbols.length > 0) result.problems.push(`symbols: ${symbols.join(", ")}`);
  }
  return result;
}

function isElf(path) {
  const magic = Buffer.alloc(4);
  const file = openSync(path, "r");
  try {
    return readSync(file, magic, 0, 4, 0) === 4 && magic.equals(Buffer.from("\x7fELF", "latin1"));
  } finally {
    closeSync(file);
  }
}

/** Every regular ELF file under `root`; links are not followed. */
export function elfFiles(root) {
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(entry.parentPath, entry.name))
    .filter(isElf)
    .sort();
}

/** Judges every ELF file of one unpacked package. */
export function checkTree(root, label, floor = GLIBC_FLOOR) {
  const errors = [];
  const report = [];
  const files = elfFiles(root);
  for (const name of BINARIES) {
    if (files.filter((path) => basename(path) === name).length !== 1) {
      errors.push(`${label}: does not hold exactly one ELF file named ${name}`);
    }
  }
  for (const path of files) {
    const shown = `${label}: ${relative(root, path).replaceAll("\\", "/")}`;
    try {
      const { highest, problems } = checkElf(path, floor);
      report.push(`${shown}: highest glibc requirement ${highest ?? "unknown"}, floor ${floor}`);
      errors.push(...problems.map((problem) => `${shown}: ${problem}`));
    } catch (error) {
      errors.push(`${shown}: ${error.message}`);
    }
  }
  return { errors, report };
}

const PACKAGES = [
  [".deb", (file, dir) => run("dpkg-deb", ["-x", file, dir])],
  [
    ".rpm",
    (file, dir) =>
      run("cpio", ["-idm", "--quiet", "--no-absolute-filenames"], {
        cwd: dir,
        input: run("rpm2cpio", [file]),
      }),
  ],
  [".tar.gz", (file, dir) => run("tar", ["-xzf", file, "--no-same-owner", "-C", dir])],
];

/** Unpacks and judges the one deb, rpm and tarball in `dist`. */
export function checkDist(dist, floor = GLIBC_FLOOR) {
  const errors = [];
  const report = [];
  const names = readdirSync(dist);
  const work = mkdtempSync(join(tmpdir(), "orcel-glibc-floor-"));
  try {
    for (const [suffix, unpack] of PACKAGES) {
      const found = names.filter((name) => name.endsWith(suffix));
      if (found.length !== 1) {
        errors.push(`${dist}: expected exactly one *${suffix}, found ${found.length}`);
        continue;
      }
      const dir = join(work, suffix.slice(1));
      mkdirSync(dir);
      unpack(resolve(dist, found[0]), dir);
      const tree = checkTree(dir, found[0], floor);
      errors.push(...tree.errors);
      report.push(...tree.report);
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  return { errors, report };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    console.error("usage: node scripts/check-linux-glibc-floor.mjs <dist-dir>");
    process.exit(2);
  }
  const { errors, report } = checkDist(process.argv[2]);
  for (const line of report) console.log(line);
  for (const error of errors) console.error(`glibc floor: ${error}`);
  if (errors.length > 0) process.exit(1);
  console.log(`Every packaged ELF file requires glibc ${GLIBC_FLOOR} or older.`);
}
