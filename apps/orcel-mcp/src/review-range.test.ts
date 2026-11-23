// .github/scripts/check-review-range.mjs against real repositories: each
// refusal, the clean cases, and failing closed when Git or an object fails.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const script = join(repo, ".github", "scripts", "check-review-range.mjs");

class Fixture {
  readonly dir = mkdtempSync(join(tmpdir(), "orcel-review-range-"));
  base = "";
  constructor() {
    this.git("init", "--quiet");
    this.git("config", "core.autocrlf", "false");
    this.git("config", "core.safecrlf", "false");
    this.write("kept.txt", "one\ntwo\nthree\n");
    this.write("moved.txt", "a line that is long enough to be seen as the same file\nand one more\n");
    this.base = this.commit("base");
  }
  git(...args: string[]): string {
    return execFileSync(
      "git",
      ["-C", this.dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, GIT_CONFIG_GLOBAL: "", GIT_CONFIG_NOSYSTEM: "1" } }
    ).trim();
  }
  write(path: string, content: string | Buffer): void {
    mkdirSync(dirname(join(this.dir, path)), { recursive: true });
    writeFileSync(join(this.dir, path), content);
  }
  commit(message: string): string {
    this.git("add", "--all");
    return this.commitIndex(message);
  }
  commitIndex(message: string): string {
    this.git("commit", "--quiet", "--allow-empty", "-m", message);
    return this.git("rev-parse", "HEAD");
  }
  /** Commits what `change` did as the head, then puts the checkout back on the base, as the workflow has it. */
  head(change: () => void): string {
    change();
    const head = this.commit("head");
    this.git("checkout", "--quiet", "--detach", this.base);
    return head;
  }
  /** A range whose head only changes the index, so file modes work on every platform. */
  headFromIndex(change: () => void): string {
    change();
    const head = this.commitIndex("head");
    this.git("checkout", "--quiet", "--force", "--detach", this.base);
    return head;
  }
  run(head: string, options: { base?: string; env?: NodeJS.ProcessEnv } = {}): { status: number | null; stdout: string; stderr: string } {
    const result = spawnSync(process.execPath, [script, options.base ?? this.base, head, this.dir], {
      encoding: "utf8",
      env: options.env ?? process.env
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  }
  passes(head: string, files: number): void {
    const result = this.run(head);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `review range: ${files} changed files, all reviewable as text\n`);
  }
  refuses(head: string, reason: RegExp, options: { base?: string; env?: NodeJS.ProcessEnv } = {}): void {
    const result = this.run(head, options);
    assert.equal(result.status, 1, result.stdout);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^review range refused: /);
    assert.match(result.stderr, reason);
  }
}

function withFixture(body: (f: Fixture) => void): void {
  const fixture = new Fixture();
  try {
    body(fixture);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true, maxRetries: 5 });
  }
}

test("a clean text diff passes: added, changed, deleted, and a path with Git's pathspec characters", () => {
  withFixture((f) => {
    f.passes(f.head(() => {
      f.write("kept.txt", "one\n2\nthree\n");
      f.write("dir/new [file] (1).txt", "new\n");
      rmSync(join(f.dir, "moved.txt"));
    }), 3);
  });
});

test("an empty diff is refused", () => {
  withFixture((f) => f.refuses(f.head(() => undefined), /contains no files/));
});

test("a binary file is refused, added, changed or deleted", () => {
  withFixture((f) => {
    const added = f.head(() => f.write("icon.bin", Buffer.from([1, 0, 2, 255])));
    f.refuses(added, /binary file cannot be reviewed: icon\.bin/);
    const withBinary = f.base;
    f.git("checkout", "--quiet", "--detach", added);
    f.base = added;
    f.refuses(f.head(() => f.write("icon.bin", Buffer.from([1, 0, 3]))), /binary file cannot be reviewed: icon\.bin/);
    f.refuses(f.head(() => rmSync(join(f.dir, "icon.bin"))), /binary file cannot be reviewed: icon\.bin/);
    assert.notEqual(withBinary, added);
  });
});

test("a diff line that does not fit in 10,000 characters with its headers is refused, added or removed", () => {
  withFixture((f) => {
    f.refuses(f.head(() => f.write("long.txt", `${"x".repeat(10_000)}\n`)), /long\.txt/);
    // The bound counts the headers: this line alone is under 10,000.
    f.refuses(f.head(() => f.write("long.txt", `${"x".repeat(9_950)}\n`)), /does not fit in 10000 characters/);
    const long = f.head(() => f.write("long.txt", `short\n${"x".repeat(9_000)}\n`));
    f.passes(long, 1);
    f.git("checkout", "--quiet", "--detach", f.base);
    f.write("huge.txt", `${"y".repeat(20_000)}\n`);
    f.base = f.commit("base with a long line");
    f.refuses(f.head(() => rmSync(join(f.dir, "huge.txt"))), /huge\.txt/);
  });
});

test("a changed file with no hunk is refused: mode only, empty added, empty deleted", () => {
  withFixture((f) => {
    f.refuses(f.headFromIndex(() => f.git("update-index", "--chmod=+x", "kept.txt")), /no text hunk.*kept\.txt/);
    const empty = f.head(() => f.write("empty.txt", ""));
    f.refuses(empty, /no text hunk.*empty\.txt/);
    f.base = empty;
    f.git("checkout", "--quiet", "--detach", empty);
    f.refuses(f.head(() => rmSync(join(f.dir, "empty.txt"))), /no text hunk.*empty\.txt/);
    // A rename of an empty file has no content to show on either side.
    f.refuses(f.headFromIndex(() => f.git("mv", "empty.txt", "renamed.txt")), /no text hunk/);
  });
});

test("a file that becomes an empty file of another type is refused", () => {
  withFixture((f) => {
    const blob = execFileSync("git", ["-C", f.dir, "hash-object", "-w", "--stdin"], { input: "kept.txt", encoding: "utf8" }).trim();
    f.git("update-index", "--add", "--cacheinfo", `120000,${blob},link`);
    f.base = f.commitIndex("base with a link");
    f.git("checkout", "--quiet", "--force", "--detach", f.base);
    const nothing = execFileSync("git", ["-C", f.dir, "hash-object", "-w", "--stdin"], { input: "", encoding: "utf8" }).trim();
    f.refuses(f.headFromIndex(() => f.git("update-index", "--cacheinfo", `100644,${nothing},link`)), /no text hunk.*link/);
    // And the other way round, where the part with no hunk comes first.
    f.git("update-index", "--add", "--cacheinfo", `100644,${nothing},link`);
    f.base = f.commitIndex("base with an empty file");
    f.git("checkout", "--quiet", "--force", "--detach", f.base);
    f.refuses(f.headFromIndex(() => f.git("update-index", "--cacheinfo", `120000,${blob},link`)), /no text hunk.*link/);
  });
});

test("a rename is read whole on both sides, so it hides nothing", () => {
  withFixture((f) => {
    f.passes(f.headFromIndex(() => f.git("mv", "moved.txt", "elsewhere.txt")), 2);
    f.git("checkout", "--quiet", "--detach", f.base);
    f.write("wide.txt", `${"z".repeat(12_000)}\n`);
    f.base = f.commit("base with a wide file");
    f.refuses(f.headFromIndex(() => f.git("mv", "wide.txt", "wide2.txt")), /wide/);
  });
});

test("what git diff --check refuses is refused", () => {
  withFixture((f) => {
    f.refuses(f.head(() => f.write("kept.txt", "one \ntwo\nthree\n")), /trailing whitespace/);
    f.refuses(f.head(() => f.write("kept.txt", "one\r\ntwo\r\nthree\r\n")), /trailing whitespace/);
    f.refuses(f.head(() => f.write("kept.txt", `one\n${"<".repeat(7)} ours\ntwo\nthree\n`)), /conflict marker/);
  });
});

test("the head's own attributes decide nothing", () => {
  withFixture((f) => {
    f.refuses(f.head(() => {
      f.write(".gitattributes", "* -whitespace\n");
      f.write("kept.txt", "one \ntwo\nthree\n");
    }), /trailing whitespace/);
    f.refuses(f.head(() => {
      f.write(".gitattributes", "* diff -whitespace\n*.bin diff\n");
      f.write("icon.bin", Buffer.from([1, 0, 2]));
    }), /binary file cannot be reviewed/);
    f.refuses(f.head(() => {
      f.write("sub/.gitattributes", "* diff -whitespace\n");
      f.write("sub/a.txt", "x \n");
    }), /trailing whitespace/);
  });
});

test("the checkout must be the clean base, and the base the merge base", () => {
  withFixture((f) => {
    const head = f.head(() => f.write("kept.txt", "one\n2\nthree\n"));
    f.git("checkout", "--quiet", "--detach", head);
    f.refuses(head, /the checkout is not the base/);
    f.git("checkout", "--quiet", "--detach", f.base);
    f.write(".gitattributes", "* -whitespace\n");
    f.refuses(head, /not clean/);
    rmSync(join(f.dir, ".gitattributes"));
    f.passes(head, 1);
    f.write("other.txt", "other\n");
    f.base = f.commit("main moved on");
    f.refuses(head, /not the merge base/);
  });
});

test("it fails closed on bad input and on Git failures", () => {
  withFixture((f) => {
    const head = f.head(() => f.write("kept.txt", "one\n2\nthree\n"));
    f.passes(head, 1);
    f.refuses("HEAD", /usage/);
    f.refuses(head.slice(0, 12), /usage/);
    f.refuses(head, /usage/, { base: "--help" });
    f.refuses("0".repeat(40), /Command failed/);
    // No git at all.
    f.refuses(head, /ENOENT/, { env: { PATH: "", Path: "" } });
    // Not a repository.
    const bare = mkdtempSync(join(tmpdir(), "orcel-review-range-none-"));
    try {
      const outside = spawnSync(process.execPath, [script, f.base, head, bare], { encoding: "utf8", env: { ...process.env, GIT_CEILING_DIRECTORIES: tmpdir() } });
      assert.equal(outside.status, 1);
      assert.match(outside.stderr, /^review range refused: Command failed/);
      assert.equal(spawnSync(process.execPath, [script], { encoding: "utf8" }).status, 1);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
    // The head's blob is gone, so its diff cannot be made.
    const blob = f.git("rev-parse", `${head}:kept.txt`);
    const object = join(f.dir, ".git", "objects", blob.slice(0, 2), blob.slice(2));
    chmodSync(object, 0o644);
    unlinkSync(object);
    f.refuses(head, /Command failed/);
  });
});
