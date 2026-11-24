// Runs in the required Governance job: no Linux tool is needed. The gate's
// programs are replaced, and the workflows and smoke scripts are read as text.
// check-linux-glibc-floor.linux.test.mjs runs the real programs on the real
// packages in the linux-packages job.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  BINARIES,
  checkDist,
  checkTree,
  compareVersions,
  GLIBC_FLOOR,
  glibcRelease,
  judge,
  PACKAGES,
  requiredVersions,
  rpmProblems,
  symbolsRequiring,
} from "./check-linux-glibc-floor.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GATE = join(REPO, "scripts", "check-linux-glibc-floor.mjs");
const read = (path) => readFileSync(join(REPO, path), "utf8").replaceAll("\r\n", "\n");
const sha256 = (content) => createHash("sha256").update(content).digest("hex");

/** A `readelf -W -V` listing that needs `names` from libc. */
function listing(...names) {
  return [
    "",
    "Version symbols section '.gnu.version' contains 9 entries:",
    " Addr: 0x0000000000000800  Offset: 0x00000800  Link: 5 (.dynsym)",
    "  000:   0 (*local*)       2 (GLIBC_2.2.5)  ",
    "",
    "Version definition section '.gnu.version_d' contains 1 entry:",
    "  000000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: lib",
    "  0x001c:   Name: GLIBC_9.9  Flags: none  Version: 2",
    "",
    "Version needs section '.gnu.version_r' contains 1 entry:",
    " Addr: 0x0000000000001000  Offset: 0x00001000  Link: 6 (.dynstr)",
    `  000000: Version: 1  File: libc.so.6  Cnt: ${names.length}`,
    ...names.map((name, at) => `  0x00${at + 1}0:   Name: ${name}  Flags: ${at % 2 ? "none" : "WEAK"}  Version: ${at + 2}`),
    "",
  ].join("\n");
}

/** A stand-in ELF file: the magic, then the listing the replaced readelf returns for it. */
const elf = (...names) => `\x7fELF${listing(...names)}`;
const OK = elf("GLIBC_2.39", "GLIBC_2.2.5");

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

const payload = (overrides = {}) => ({
  ...Object.fromEntries(BINARIES.map((name) => [`usr/lib/orcel/${name}`, OK])),
  "usr/share/doc/orcel/README.md": "not an ELF file",
  ...overrides,
});

function dump(files) {
  return [
    "/usr/lib/orcel 0 1700000000 0000000000000000000000000000000000000000000000000000000000000000 040755 root root 0 0 0 X",
    ...Object.entries(files).map(
      ([path, content]) =>
        `/${path} ${Buffer.byteLength(content)} 1700000000 ${sha256(content)} 0100755 root root 0 0 0 X`,
    ),
    "",
  ].join("\n");
}

/** Judges three packages whose payloads are given by suffix, with every program replaced. */
function judgeDist(payloads = {}, tools = {}, ...floor) {
  const of = (suffix) => payloads[suffix] ?? payload();
  const all = {
    unpack(suffix, file, dir) {
      assert.ok(file.endsWith(suffix));
      for (const [path, content] of Object.entries(of(suffix))) {
        mkdirSync(dirname(join(dir, path)), { recursive: true });
        writeFileSync(join(dir, path), content);
      }
    },
    rpmDump: () => dump(of(".rpm")),
    versions: (path) => readFileSync(path, "utf8").slice(4),
    symbols: () => "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND newer@GLIBC_2.43 (4)",
    ...tools,
  };
  return withTree({ "o.deb": "", "o.rpm": "", "o.tar.gz": "", "SHA256SUMS-linux.txt": "" }, (root) =>
    checkDist(root, all, ...floor));
}

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
  const lines = listing("GLIBC_2.39", "GLIBC_2.2.5").split("\n");
  assert.deepEqual(requiredVersions(lines.join("\n")), ["GLIBC_2.39", "GLIBC_2.2.5"]);
  const needs = lines.findIndex((line) => line.startsWith("Version needs"));
  assert.throws(() => requiredVersions(lines.toSpliced(needs + 3, 1).join("\n")), /announced 2 required .* listed 1/);
  assert.throws(() => requiredVersions(lines.toSpliced(needs + 2, 1).join("\n")), /announced 1 needed .* listed 0/);
  assert.throws(() => requiredVersions(lines.toSpliced(needs + 1).join("\n")), /announced 1 needed .* listed 0/);
  const more = lines.with(needs, "Version needs section '.gnu.version_r' contains 2 entries:");
  assert.throws(() => requiredVersions(more.join("\n")), /announced 2 needed .* listed 1/);
  const uncounted = lines.with(needs, "Version needs section '.gnu.version_r':");
  assert.throws(() => requiredVersions(uncounted.join("\n")), /without a count/);
  assert.deepEqual(requiredVersions("\nNo version information found in this file.\n"), []);
});

test("the failure names the symbols that need the newer glibc", () => {
  const symbols = [
    "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)",
    "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND newer@GLIBC_2.43 (4)",
    "     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND other@GLIBC_2.4 (5)",
  ].join("\n");
  assert.deepEqual(symbolsRequiring(symbols, ["GLIBC_2.43"]), ["newer@GLIBC_2.43"]);
});

test("three good packages pass at the default floor, and every file's maximum is printed", () => {
  const { errors, report } = judgeDist();
  assert.deepEqual(errors, []);
  assert.equal(report.length, 9);
  assert.ok(report.every((line) => line.endsWith("highest glibc requirement 2.39, floor 2.39")), report.join("\n"));
  assert.equal(judgeDist({}, {}, "2.38").errors.length, 9, "a lower floor refuses all nine");
});

test("one file above the default floor fails in any package, and the report stays whole", () => {
  for (const suffix of PACKAGES) {
    const { errors, report } = judgeDist({
      [suffix]: payload({ "usr/lib/orcel/orceld": elf("GLIBC_2.2.5", "GLIBC_2.40", "GLIBC_2.43") }),
    });
    const text = errors.join("\n");
    assert.match(text, new RegExp(`^o\\${suffix}: usr/lib/orcel/orceld: requires GLIBC_2\\.40, GLIBC_2\\.43, newer`, "m"));
    assert.match(text, /symbols: newer@GLIBC_2\.43/);
    assert.match(text, /2 different builds of orceld/);
    assert.equal(report.length, 9);
    assert.equal(report.filter((line) => line.includes("highest glibc requirement 2.43")).length, 1);
  }
  const just = judgeDist({ ".deb": payload({ "opt/extra": elf("GLIBC_2.40") }) });
  assert.match(just.errors.join("\n"), /opt\/extra: requires GLIBC_2\.40/, "every ELF file counts, weak ones too");
});

test("a package that does not unpack fails, and the others are still judged and printed", () => {
  for (const broken of PACKAGES) {
    const { errors, report } = judgeDist({}, {
      unpack(suffix, file, dir) {
        if (suffix === broken) throw new Error("unpacker exited 1");
        for (const [path, content] of Object.entries(payload())) {
          mkdirSync(dirname(join(dir, path)), { recursive: true });
          writeFileSync(join(dir, path), content);
        }
      },
    });
    assert.deepEqual(errors, [`o${broken}: unpacker exited 1`]);
    assert.equal(report.length, 7);
    assert.ok(report.includes(`o${broken}: not judged`));
  }
  const header = judgeDist({}, { rpmDump: () => { throw new Error("rpm exited 1"); } });
  assert.deepEqual(header.errors, ["o.rpm: rpm exited 1"]);
});

test("an unreadable ELF file fails and is still printed", () => {
  const { errors, report } = judgeDist({}, {
    versions(path) {
      if (basename(path) === "orcel-contain") throw new Error("readelf exited 1");
      return listing("GLIBC_2.39");
    },
  });
  assert.equal(errors.length, 3);
  assert.equal(report.filter((line) => line.includes("orcel-contain: highest glibc requirement unknown")).length, 3);
});

test("a missing or doubled binary, and an empty or missing package, fail", () => {
  const files = payload();
  delete files["usr/lib/orcel/orcel-contain"];
  assert.deepEqual(judgeDist({ ".deb": files }).errors, ["o.deb: does not hold exactly one ELF file named orcel-contain"]);
  assert.match(judgeDist({ ".deb": payload({ "opt/orceld": OK }) }).errors.join(), /exactly one ELF file named orceld/);
  assert.match(judgeDist({ ".deb": payload({ "usr/lib/orcel/orceld": "text" }) }).errors.join(), /named orceld/);
  withTree({}, (root) => assert.equal(checkTree(root, "x").errors.length, BINARIES.length));
  const none = withTree({ "a.txt": "" }, (root) => checkDist(root));
  assert.equal(none.errors.length, 3);
  for (const suffix of PACKAGES) {
    assert.ok(none.errors.some((error) => error.includes(`exactly one *${suffix}, found 0`)), none.errors.join("\n"));
  }
  const two = withTree({ "a.deb": "", "b.deb": "" }, (root) => checkDist(root));
  assert.match(two.errors.join("\n"), /exactly one \*\.deb, found 2/);
});

test("the rpm's files are exactly the ones its header records", () => {
  const files = payload();
  const problems = (listed, unpacked = files) => withTree(unpacked, (root) => rpmProblems(listed, root)).join("\n");
  assert.equal(problems(dump(files)), "");
  const { "usr/share/doc/orcel/README.md": _, ...fewer } = files;
  assert.match(problems(dump(files), fewer), /README\.md was not unpacked/);
  assert.match(problems(dump(fewer)), /README\.md was unpacked but the header does not list it/);
  assert.match(
    problems(dump(files), { ...files, "usr/share/doc/orcel/README.md": "NOT an ELF file" }),
    /README\.md was unpacked with other bytes/,
  );
  assert.match(problems(dump(files).replace(" 15 ", " 16 ")), /README\.md was unpacked with other bytes/);
  assert.match(problems(""), /the header lists no file/);
  assert.match(problems(dump({})), /the header lists no file/);
  assert.match(problems(`${dump(files)}garbage\n`), /unreadable header line: garbage/);
  assert.match(problems(dump(files) + dump({ "usr/lib/orcel/orceld": OK })), /orceld is listed twice/);
  assert.match(problems(dump(files).replace("0100755", "0120777")), /not a regular file/);
  assert.match(problems(dump(files).replace(sha256(OK), "0".repeat(32))), /SHA-256 digest/);
  const short = judgeDist({}, { rpmDump: () => dump(payload({ "usr/lib/orcel/late": "x" })) });
  assert.deepEqual(short.errors, ["o.rpm: /usr/lib/orcel/late was not unpacked"], "checkDist uses it");
});

test("the command line exits 1 on a bad directory and 2 without one", () => {
  withTree({}, (root) => {
    const bad = spawnSync(process.execPath, [GATE, root], { encoding: "utf8" });
    assert.equal(bad.status, 1);
    assert.equal(bad.stderr.match(/^glibc floor: /gm)?.length, 3);
    assert.ok(!bad.stdout.includes("or older"));
  });
  assert.equal(spawnSync(process.execPath, [GATE]).status, 2);
  assert.equal(spawnSync(process.execPath, [GATE, ".", "extra"]).status, 2);
});

// The pins below are text comparisons. They hold the workflow steps and the
// smoke scripts to what was reviewed; a deliberate change updates them here,
// in the same pull request. They cannot show that a step works.

/**
 * One job: the lines before its steps, and each step's text. Comment lines
 * between jobs and steps are left out, and only those: inside a script a
 * comment can cut a continued command.
 */
function job(workflow, name) {
  const lines = read(`.github/workflows/${workflow}`).split("\n").filter((line) => !/^ {0,6}#/.test(line));
  const starts = lines.flatMap((line, at) => (line === `  ${name}:` ? [at] : []));
  assert.equal(starts.length, 1, `${workflow} has one job ${name}`);
  const rest = lines.slice(starts[0] + 1);
  const end = rest.findIndex((line) => /^ {0,2}\S/.test(line));
  const body = end < 0 ? rest : rest.slice(0, end);
  const steps = body.indexOf("    steps:");
  return {
    head: body.slice(0, steps).join("\n"),
    steps: body.slice(steps + 1).join("\n").split(/\n(?= {6}- )/).map((step) => step.trimEnd()),
    text: body.join("\n"),
  };
}

const named = (steps, name) => {
  const found = steps.filter((step) => step.startsWith(`      - name: ${name}\n`));
  assert.equal(found.length, 1, `one step named ${name}`);
  return found[0];
};

const APPROVAL_HELPER = `      - name: Build the XP-10 approval helper (release, locked, its own workspace)
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends libgtk-4-dev libarchive-tools rpm
          cargo build --release --locked --manifest-path apps/orcel-approval-helper-linux/Cargo.toml`;
const PACKAGE_ARGS = `target/release/orceld apps/orcel-contain/target/release/orcel-contain \\
            apps/orcel-approval-helper-linux/target/release/orcel-approval-helper-linux`;

const CI_STEPS = [
  APPROVAL_HELPER,
  `      - name: Build the deb, rpm and tarball
        run: |
          version=$(sed -n 's/^version = "\\(.*\\)"$/\\1/p' Cargo.toml | head -n 1)
          echo "VERSION=$version" >> "$GITHUB_ENV"
          bash distribution/linux/package.sh "$version" ${PACKAGE_ARGS} "$DIST"
          ls -l "$DIST"`,
  `      - name: No packaged ELF file needs a glibc newer than the documented floor
        run: |
          ldd --version
          pkg-config --modversion gtk4
          node scripts/check-linux-glibc-floor.mjs "$DIST"`,
  `      - name: The glibc floor check on the real packages
        run: ORCEL_LINUX_DIST="$DIST" node --test scripts/check-linux-glibc-floor.linux.test.mjs`,
  `      - name: Install and start the deb in Ubuntu 24.04
        run: bash distribution/linux/smoke-ubuntu.sh "$VERSION" "$DIST"`,
  `      - name: Install the rpm in Fedora 41
        run: |
          docker run --rm -v "$DIST:/dist:ro" -v "$PWD/scripts:/probe:ro" -v "$PWD/distribution/linux:/smoke:ro" \\
            docker.io/library/fedora@sha256:f1a3fab47bcb3c3ddf3135d5ee7ba8b7b25f2e809a47440936212a3a50957f3d \\
            bash -euxc '
              rpm=/dist/orcel-'"$VERSION"'-1.x86_64.rpm
              rpm -qplv "$rpm"
              test -z "$(rpm -qp --scripts "$rpm")"
              if rpm -qplv "$rpm" | awk "{ print \\$1 }" | grep -E "[sStT]"; then exit 1; fi
              dnf install -y --setopt=install_weak_deps=False "$rpm" python3
              rpm -V orcel
              bash /smoke/smoke-installed.sh daemon
              mkdir -p /root/ws
              ORCEL_WORKSPACES_JSON="[{\\"id\\":\\"ci\\",\\"root\\":\\"/root/ws\\"}]" python3 /probe/linux-orceld-probe.py exec /usr/lib/orcel/orceld ci
              dnf install -y --setopt=install_weak_deps=False gtk4
              bash /smoke/smoke-installed.sh helper
              dnf remove -y orcel
              test ! -e /usr/lib/orcel
              test ! -e /usr/share/doc/orcel
            '`,
];

const RELEASE_STEPS = [
  APPROVAL_HELPER,
  `      - name: Install the pinned nfpm (checksum-verified)
        run: |
          bash distribution/linux/install-nfpm.sh "$RUNNER_TEMP/nfpm-bin"
          echo "$RUNNER_TEMP/nfpm-bin" >> "$GITHUB_PATH"`,
  `      - name: Build the deb, rpm and tarball
        run: |
          bash distribution/linux/package.sh "$VERSION" ${PACKAGE_ARGS} "$RUNNER_TEMP/linux-dist"`,
  `      - name: No packaged ELF file needs a glibc newer than the documented floor
        run: node scripts/check-linux-glibc-floor.mjs "$RUNNER_TEMP/linux-dist"`,
  `      - name: Install and start the deb in Ubuntu 24.04
        run: bash distribution/linux/smoke-ubuntu.sh "$VERSION" "$RUNNER_TEMP/linux-dist"`,
  `      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: release-linux
          path: |
            \${{ runner.temp }}/linux-dist/*.deb
            \${{ runner.temp }}/linux-dist/*.rpm
            \${{ runner.temp }}/linux-dist/*.tar.gz
            \${{ runner.temp }}/linux-dist/SHA256SUMS-linux.txt
          if-no-files-found: error
          retention-days: 30`,
];

const withoutVersionComment = (step) => step.replace(/ # v[\d.]+$/m, "");

/** Keys that would skip, replace or excuse a step, at job or step level. */
function noEscape(text, where) {
  for (const key of ["if", "container", "continue-on-error", "shell", "defaults", "services", "strategy", "<<"]) {
    const found = text.split("\n").filter((line) => new RegExp(`^ {4,8}(- )?["']?${key}["']?\\s*:`).test(line));
    assert.deepEqual(found, [], `${where}: no ${key}:`);
  }
}

test("both package builds run on ubuntu-24.04 with the reviewed job settings", () => {
  assert.equal(
    job("ci.yml", "linux-packages").head,
    `    name: Linux packages / ubuntu-24.04
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    env:
      DIST: \${{ github.workspace }}/../linux-dist`,
  );
  assert.equal(
    job("release.yml", "build-linux").head,
    `    name: Release build / ubuntu-24.04 (Linux packages)
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    permissions:
      contents: read
    env:
      TAG: \${{ github.ref_name }}`,
  );
  for (const [workflow, name] of [["ci.yml", "linux-packages"], ["release.yml", "build-linux"]]) {
    noEscape(job(workflow, name).text, `${workflow} ${name}`);
    const top = read(`.github/workflows/${workflow}`).split("\n").filter((line) => /^[^\s#]/.test(line));
    assert.deepEqual(top.map((line) => line.split(":")[0]), ["name", "on", "permissions", "jobs"], workflow);
  }
});

test("the CI steps that build, check and start the packages are the reviewed ones, in order", () => {
  const { steps, text } = job("ci.yml", "linux-packages");
  const positions = CI_STEPS.map((want) => {
    const name = /- name: (.*)\n/.exec(want)[1];
    assert.equal(named(steps, name), want);
    return steps.indexOf(want);
  });
  assert.deepEqual(positions, positions.toSorted((a, b) => a - b));
  assert.equal(positions[2], positions[1] + 1, "the floor check follows packaging at once");
  // Nothing rebuilds the packages, and only these lines use their directory.
  assert.equal(text.split("package.sh ").length - 1, 1);
  assert.equal(text.split("linux-dist").length - 1, 1);
  assert.deepEqual(
    text.split("\n").filter((line) => /\bDIST\b/.test(line)).map((line) => line.trim()),
    [
      "DIST: ${{ github.workspace }}/../linux-dist",
      'apps/orcel-approval-helper-linux/target/release/orcel-approval-helper-linux "$DIST"',
      'ls -l "$DIST"',
      'node scripts/check-linux-glibc-floor.mjs "$DIST"',
      'run: ORCEL_LINUX_DIST="$DIST" node --test scripts/check-linux-glibc-floor.linux.test.mjs',
      'deb="$DIST/orcel_${VERSION}-1_amd64.deb"',
      'tar -tvzf "$DIST/orcel-${VERSION}-linux-x86_64.tar.gz"',
      '(cd "$DIST" && sha256sum --check --strict SHA256SUMS-linux.txt)',
      'mkdir "$RUNNER_TEMP/tampered" && cp "$DIST"/* "$RUNNER_TEMP/tampered/"',
      'sudo apt-get install -y "$DIST/orcel_${VERSION}-1_amd64.deb"',
      'tar -xzf "$DIST/orcel-${VERSION}-linux-x86_64.tar.gz" --strip-components=1 -C "$HOME/.local/share/orcel"',
      'run: bash distribution/linux/smoke-ubuntu.sh "$VERSION" "$DIST"',
      'docker run --rm -v "$DIST:/dist:ro" -v "$PWD/scripts:/probe:ro" -v "$PWD/distribution/linux:/smoke:ro" \\',
    ],
  );
});

test("the release build ends with the reviewed steps, and publishing needs it", () => {
  const { steps, text } = job("release.yml", "build-linux");
  assert.deepEqual(steps.slice(-RELEASE_STEPS.length).map(withoutVersionComment), RELEASE_STEPS);
  assert.ok(!text.includes("|| true"));
  assert.equal(text.split("linux-dist").length - 1, 7, "no other step touches the packages");
  const { head } = job("release.yml", "publish");
  assert.ok(head.split("\n").includes("    needs: [build-windows, build-linux]"));
  noEscape(head, "release.yml publish");
});

test("the smoke scripts are the reviewed ones", () => {
  const ubuntu = read("distribution/linux/smoke-ubuntu.sh");
  const installed = read("distribution/linux/smoke-installed.sh");
  // What each must do, said first so that a failure is readable.
  assert.match(ubuntu, /^image=docker\.io\/library\/ubuntu@sha256:[0-9a-f]{64}$/m);
  assert.equal(ubuntu.match(/\bimage=/g).length, 1);
  assert.equal(ubuntu.match(/docker run/g).length, 1);
  assert.match(ubuntu, /DEBIAN_FRONTEND=noninteractive "\$image" \\\n/);
  assert.deepEqual(
    [...ubuntu.matchAll(/ -v "([^"]*)"/g)].map((found) => found[1]),
    ["$dist:/dist:ro", "$repo/distribution/linux:/smoke:ro", "$repo/scripts:/probe:ro"],
    "only these mounts: the checkout's .git/config holds CI's token",
  );
  for (const call of ["smoke-installed.sh daemon", "smoke-installed.sh helper", "linux-orceld-probe.py exec"]) {
    assert.ok(ubuntu.includes(call), call);
  }
  for (const phrase of ['"not found"', '"not defined in file"', '"undefined symbol"']) {
    assert.ok(installed.includes(phrase), phrase);
  }
  for (const text of [ubuntu, installed]) assert.doesNotMatch(text, /exit 0|\|\| true|\|\| :|set \+e/);
  // Then every byte.
  assert.equal(sha256(ubuntu), "f1e0a023f2a324d72b34050967fa0c52ff9954ee8529b215aae573e2b3457964", "smoke-ubuntu.sh changed: review it and update this pin");
  assert.equal(sha256(installed), "a03a4c788d6a80646241fddc9f98536161f8889ca2577e72c6c062ff889d658d", "smoke-installed.sh changed: review it and update this pin");
});

test("the documented floor is the one the gate enforces", () => {
  assert.equal(GLIBC_FLOOR, "2.39");
  const readme = read("distribution/linux/README.md");
  assert.ok(readme.includes(`glibc ${GLIBC_FLOOR}`), "README.md names the floor");
  assert.ok(readme.includes("### deb (Ubuntu 24.04 and later) or rpm (Fedora 41 and later)"));
});
