#!/usr/bin/env node
// Linux package gate: no ELF file in the deb, the rpm or the per-user tarball
// may require a glibc newer than the documented floor (distribution/linux/
// README.md: Ubuntu 24.04 and later, Fedora 41 and later).
//
// Every requirement `readelf -V` lists counts, weak ones included: a weak
// requirement would still load on an older glibc, but whatever needs it is
// untested there. Anything the gate cannot read or rank fails: a missing
// package, a package that does not unpack, a missing binary, an ELF file with
// no GLIBC_ requirement, a version list that does not add up, or a GLIBC_
// name it does not know.
//
// The rpm is unpacked with bsdtar: rpm2cpio exits 1 on nfpm's rpm, whose
// archive size tag does not count the cpio headers. What bsdtar wrote is
// compared, file by file, with the digests in the rpm's own header, and the
// three packages must hold the same binaries byte for byte.
//
// Usage (Linux; needs dpkg-deb, bsdtar, rpm, tar and readelf):
//   node scripts/check-linux-glibc-floor.mjs <dist-dir>

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The oldest glibc the packages support: Ubuntu 24.04's. Fedora 41 has 2.40. */
export const GLIBC_FLOOR = "2.39";

/** The binaries every package must hold. */
export const BINARIES = ["orcel-approval-helper-linux", "orcel-contain", "orceld"];

export const PACKAGES = [".deb", ".rpm", ".tar.gz"];

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
  let announcedFiles = 0;
  let files = 0;
  let announcedNames = 0;
  for (const line of listing.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inNeeds = line.startsWith("Version needs section ");
      if (inNeeds) {
        const entries = / contains (\d+) entr(?:y|ies):$/.exec(line);
        if (!entries) throw new Error(`readelf announced a needs section without a count: ${line}`);
        announcedFiles += Number(entries[1]);
      }
    }
    if (!inNeeds) continue;
    const file = /^\s+(?:0x)?[0-9a-f]+: Version: \d+\s+File: \S+\s+Cnt: (\d+)\s*$/.exec(line);
    if (file) {
      files += 1;
      announcedNames += Number(file[1]);
      continue;
    }
    const version = /^\s+(?:0x)?[0-9a-f]+:\s+Name: (\S+)\s+Flags: .+\s+Version: \d+\s*$/.exec(line);
    if (version) names.push(version[1]);
  }
  if (files !== announcedFiles) {
    throw new Error(`readelf announced ${announcedFiles} needed files and listed ${files}`);
  }
  if (names.length !== announcedNames) {
    throw new Error(`readelf announced ${announcedNames} required versions and listed ${names.length}`);
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

/** The symbols of a `readelf -W --dyn-syms` listing that carry one of `versions`, for the failure message. */
export function symbolsRequiring(listing, versions) {
  const symbols = listing.match(/\S+@GLIBC_\S+/g) ?? [];
  return symbols.filter((symbol) => versions.some((version) => symbol.endsWith(`@${version}`)));
}

function run(command, args) {
  const done = spawnSync(command, args, { maxBuffer: 1 << 28, env: { ...process.env, LC_ALL: "C" } });
  if (done.error) throw new Error(`${command}: ${done.error.message}`);
  if (done.status !== 0) {
    throw new Error(`${command} exited ${done.status ?? done.signal}: ${done.stderr.toString().trim()}`);
  }
  return done.stdout.toString();
}

/** The programs the gate runs; its tests replace them. */
export const SYSTEM = {
  unpack(suffix, file, dir) {
    if (suffix === ".deb") run("dpkg-deb", ["-x", file, dir]);
    else if (suffix === ".rpm") run("bsdtar", ["-xf", file, "--no-same-owner", "--no-same-permissions", "-C", dir]);
    else if (suffix === ".tar.gz") run("tar", ["-xzf", file, "--no-same-owner", "-C", dir]);
    else throw new Error(`no way to unpack *${suffix}`);
  },
  rpmDump: (file) => run("rpm", ["-qp", "--dump", file]),
  versions: (path) => run("readelf", ["-W", "-V", path]),
  symbols: (path) => run("readelf", ["-W", "--dyn-syms", path]),
};

function isElf(path) {
  const magic = Buffer.alloc(4);
  const file = openSync(path, "r");
  try {
    return readSync(file, magic, 0, 4, 0) === 4 && magic.equals(Buffer.from("\x7fELF", "latin1"));
  } finally {
    closeSync(file);
  }
}

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

/** Everything under `root` that is not a directory, as [path from `root`, entry]; links are not followed. */
function entries(root) {
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => !entry.isDirectory())
    .map((entry) => [relative(root, join(entry.parentPath, entry.name)).replaceAll("\\", "/"), entry])
    .sort(([a], [b]) => (a < b ? -1 : 1));
}

/** How the files under `root` differ from an `rpm -qp --dump` listing: every file, its size and its SHA-256. */
export function rpmProblems(dump, root) {
  const problems = [];
  const listed = new Map();
  for (const line of dump.split("\n").filter((text) => text !== "")) {
    const fields = line.split(" ");
    const [path, size, , digest, mode] = fields;
    if (fields.length !== 11 || !path.startsWith("/") || !/^0\d{5,6}$/.test(mode)) {
      problems.push(`unreadable header line: ${line}`);
      continue;
    }
    const type = Number.parseInt(mode, 8) & 0o170000;
    if (type === 0o040000) continue;
    if (type !== 0o100000 || !/^[0-9a-f]{64}$/.test(digest)) {
      problems.push(`${path} is not a regular file with a SHA-256 digest`);
    } else if (listed.has(path)) {
      problems.push(`${path} is listed twice`);
    } else {
      listed.set(path, { size: Number(size), digest });
    }
  }
  if (listed.size === 0) problems.push("the header lists no file");
  const found = new Map(entries(root).map(([path, entry]) => [`/${path}`, entry]));
  for (const [path, { size, digest }] of listed) {
    if (!found.get(path)?.isFile()) {
      problems.push(`${path} was not unpacked`);
      continue;
    }
    const unpacked = join(root, path);
    if (readFileSync(unpacked).length !== size || sha256(unpacked) !== digest) {
      problems.push(`${path} was unpacked with other bytes than the header records`);
    }
  }
  for (const path of found.keys()) {
    if (!listed.has(path)) problems.push(`${path} was unpacked but the header does not list it`);
  }
  return problems;
}

/** Judges every ELF file of one unpacked package. `binaries` maps each expected binary to its SHA-256. */
export function checkTree(root, label, tools = SYSTEM, floor = GLIBC_FLOOR) {
  const errors = [];
  const report = [];
  const binaries = new Map();
  const files = entries(root)
    .filter(([path, entry]) => entry.isFile() && isElf(join(root, path)))
    .map(([path]) => path);
  for (const name of BINARIES) {
    const found = files.filter((path) => basename(path) === name);
    if (found.length === 1) binaries.set(name, sha256(join(root, found[0])));
    else errors.push(`${label}: does not hold exactly one ELF file named ${name}`);
  }
  for (const path of files) {
    const shown = `${label}: ${path}`;
    let highest = null;
    try {
      const result = judge(requiredVersions(tools.versions(join(root, path))), floor);
      highest = result.highest;
      errors.push(...result.problems.map((problem) => `${shown}: ${problem}`));
      if (result.above.length > 0) {
        const symbols = symbolsRequiring(tools.symbols(join(root, path)), result.above);
        if (symbols.length > 0) errors.push(`${shown}: symbols: ${symbols.join(", ")}`);
      }
    } catch (error) {
      errors.push(`${shown}: ${error.message}`);
    }
    report.push(`${shown}: highest glibc requirement ${highest ?? "unknown"}, floor ${floor}`);
  }
  return { errors, report, binaries };
}

/** Unpacks and judges the one deb, rpm and tarball in `dist`; one package's failure does not hide the others'. */
export function checkDist(dist, tools = SYSTEM, floor = GLIBC_FLOOR) {
  const errors = [];
  const report = [];
  const digests = new Map(BINARIES.map((name) => [name, new Set()]));
  const names = readdirSync(dist);
  const work = mkdtempSync(join(tmpdir(), "orcel-glibc-floor-"));
  try {
    for (const suffix of PACKAGES) {
      const found = names.filter((name) => name.endsWith(suffix));
      if (found.length !== 1) {
        errors.push(`${dist}: expected exactly one *${suffix}, found ${found.length}`);
        continue;
      }
      const [name] = found;
      try {
        const file = resolve(dist, name);
        const dir = join(work, suffix.slice(1));
        mkdirSync(dir);
        tools.unpack(suffix, file, dir);
        if (suffix === ".rpm") {
          errors.push(...rpmProblems(tools.rpmDump(file), dir).map((problem) => `${name}: ${problem}`));
        }
        const tree = checkTree(dir, name, tools, floor);
        errors.push(...tree.errors);
        report.push(...tree.report);
        for (const [binary, digest] of tree.binaries) digests.get(binary).add(digest);
      } catch (error) {
        errors.push(`${name}: ${error.message}`);
        report.push(`${name}: not judged`);
      }
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  for (const [binary, seen] of digests) {
    if (seen.size > 1) errors.push(`the packages hold ${seen.size} different builds of ${binary}`);
  }
  return { errors, report };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
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
