#!/usr/bin/env python3
"""Migrate Orcel's published core npm identity to @orcel/orcel.

This helper is intentionally narrow: it changes npm package identity references while
preserving product branding, the `orcel` CLI binary, `.orcel` state paths, `/orcel`
HTTP routes, historical changelogs/research, provenance, and external compatibility
identifiers.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OLD = "orcel"
NEW = "@orcel/orcel"

SKIP_PREFIXES = (
    ".orcel-migration/",
    "research/",
)
SKIP_EXACT = {
    ".github/scripts/migrate-orcel-npm-scope.py",
    ".github/workflows/npm-scope-migration.yml",
}
DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
TEXT_SUFFIXES = {
    ".cjs",
    ".css",
    ".cts",
    ".html",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".md",
    ".mdx",
    ".mjs",
    ".mts",
    ".sh",
    ".svelte",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".yaml",
    ".yml",
}
# Count only actual route-shaped `/orcel/` occurrences. The scoped npm identity
# contains the substring `/orcel/` inside `@orcel/orcel/`; there the slash is
# preceded by the alphanumeric scope name and must not be treated as a route.
PUBLIC_ROUTE_PATTERN = re.compile(r"(?<![A-Za-z0-9@._-])/orcel/")


def tracked_files() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [entry for entry in raw.decode().split("\0") if entry]


def is_active_text(rel: str) -> bool:
    if rel in SKIP_EXACT:
        return False
    if rel.endswith("CHANGELOG.md"):
        return False
    if rel.startswith(SKIP_PREFIXES):
        return False
    return Path(rel).suffix.lower() in TEXT_SUFFIXES or Path(rel).name in {
        "AGENTS.md",
        "Dockerfile",
        "README",
    }


def public_route_count(text: str) -> int:
    return len(PUBLIC_ROUTE_PATTERN.findall(text))


def replace_quoted_subpaths(text: str) -> str:
    # A quoted `orcel/...` value is a package subpath. HTTP routes have a leading
    # slash (`/orcel/...`) and local state has a leading dot (`.orcel/...`), so
    # neither shape matches this boundary.
    pattern = re.compile(r"([\"'])orcel/([^\"']+)\1")
    text = pattern.sub(lambda m: f"{m.group(1)}{NEW}/{m.group(2)}{m.group(1)}", text)
    text = text.replace("`orcel/", f"`{NEW}/")
    return text


def replace_bare_imports(text: str) -> str:
    patterns = (
        (re.compile(r"(\bfrom\s+)([\"'])orcel\2"), rf"\1\2{NEW}\2"),
        (re.compile(r"(\bimport\s+)([\"'])orcel\2"), rf"\1\2{NEW}\2"),
        (re.compile(r"(\bimport\s*\(\s*)([\"'])orcel\2"), rf"\1\2{NEW}\2"),
        (re.compile(r"(\brequire\s*\(\s*)([\"'])orcel\2"), rf"\1\2{NEW}\2"),
    )
    for pattern, replacement in patterns:
        text = pattern.sub(replacement, text)
    return text


def replace_workspace_dependency_keys(text: str) -> str:
    # Normal JSON/YAML-ish package manifests.
    text = re.sub(
        r'"orcel"(\s*:\s*"workspace:[^"]*")',
        rf'"{NEW}"\1',
        text,
    )
    # Escaped package.json bodies embedded in tests/generated source.
    text = re.sub(
        r'\\"orcel\\"(\s*:\s*\\"workspace:[^\\"]*\\")',
        rf'\\"{NEW}\\"\1',
        text,
    )
    return text


def replace_inline_dependency_object_keys(text: str) -> str:
    # Generated/test package manifests sometimes use JS object shorthand keys.
    for field in DEPENDENCY_FIELDS:
        pattern = re.compile(
            rf"({field}\s*:\s*\{{\s*)orcel(\s*:)",
            flags=re.MULTILINE,
        )
        text = pattern.sub(rf'\1"{NEW}"\2', text)
    return text


def replace_package_identity_guards(text: str) -> str:
    # Central and bootstrap-only package-name constants.
    text = re.sub(
        r'(ORCEL_PACKAGE_NAME\s*=\s*)([\"\'])orcel\2',
        rf'\1\2{NEW}\2',
        text,
    )

    # Package-resolution/bundler guards. Do not touch generic service/route IDs.
    for lhs in ("source", "specifier", "moduleSpecifier", "request", "packageName"):
        text = text.replace(f'{lhs} === "orcel"', f'{lhs} === "{NEW}"')
        text = text.replace(f"{lhs} === 'orcel'", f"{lhs} === '{NEW}'")
        text = text.replace(
            f'{lhs}.startsWith("orcel/")', f'{lhs}.startsWith("{NEW}/")'
        )
        text = text.replace(
            f"{lhs}.startsWith('orcel/')", f"{lhs}.startsWith('{NEW}/')"
        )

    # Project-root package detection.
    text = text.replace("dependencies.orcel", f'dependencies["{NEW}"]')
    text = text.replace("dependencies?.orcel", f'dependencies?.["{NEW}"]')
    text = text.replace("packageJson.dependencies.orcel", f'packageJson.dependencies["{NEW}"]')
    text = text.replace(
        "packageJson.dependencies?.orcel", f'packageJson.dependencies?.["{NEW}"]'
    )
    return text


def replace_installation_surface(text: str) -> str:
    replacements = (
        ("pnpm add orcel", f"pnpm add {NEW}"),
        ("npm install orcel", f"npm install {NEW}"),
        ("npm i orcel", f"npm i {NEW}"),
        ("yarn add orcel", f"yarn add {NEW}"),
        ("bun add orcel", f"bun add {NEW}"),
        ("pnpm dlx orcel", f"pnpm dlx {NEW}"),
        ("npx orcel", f"npx {NEW}"),
        ("--filter orcel", f"--filter {NEW}"),
        ("--filter=orcel", f"--filter={NEW}"),
        ("node_modules/orcel/", f"node_modules/{NEW}/"),
        ("node_modules/orcel`", f"node_modules/{NEW}`"),
        ("node_modules/orcel\"", f"node_modules/{NEW}\""),
        ("node_modules/orcel'", f"node_modules/{NEW}'"),
        ("npmjs.com/package/orcel", f"npmjs.com/package/{NEW}"),
    )
    for before, after in replacements:
        text = text.replace(before, after)

    # Runtime benchmark fixture that materializes node_modules manually.
    text = text.replace(
        'join(root, "node_modules", "orcel")',
        'join(root, "node_modules", "@orcel", "orcel")',
    )
    return text


def migrate_text(rel: str, text: str) -> str:
    original_route_count = public_route_count(text)
    original_state_count = text.count(".orcel/")

    if rel == "packages/orcel/package.json":
        text = text.replace('"name": "orcel"', f'"name": "{NEW}"', 1)

    text = replace_workspace_dependency_keys(text)
    text = replace_inline_dependency_object_keys(text)
    text = replace_bare_imports(text)
    text = replace_quoted_subpaths(text)
    text = replace_package_identity_guards(text)
    text = replace_installation_surface(text)

    if rel == "scripts/assert-changeset-publish-packages.mjs":
        text = text.replace('"orcel"', f'"{NEW}"')
        text = text.replace("'orcel'", f"'{NEW}'")

    if public_route_count(text) != original_route_count:
        raise RuntimeError(f"public route surface changed unexpectedly: {rel}")
    if text.count(".orcel/") != original_state_count:
        raise RuntimeError(f"local state path surface changed unexpectedly: {rel}")
    return text


def migrate() -> list[str]:
    changed: list[str] = []
    for rel in tracked_files():
        if not is_active_text(rel):
            continue
        path = ROOT / rel
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        updated = migrate_text(rel, text)
        if updated != text:
            path.write_bytes(updated.encode("utf-8"))
            changed.append(rel)
    return changed


def read_active_texts() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for rel in tracked_files():
        if not is_active_text(rel):
            continue
        try:
            result.append((rel, (ROOT / rel).read_bytes().decode("utf-8")))
        except UnicodeDecodeError:
            pass
    return result


def assert_package_json_dependencies() -> None:
    failures: list[str] = []
    for rel in tracked_files():
        if not rel.endswith("package.json"):
            continue
        path = ROOT / rel
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        for field in DEPENDENCY_FIELDS:
            deps = payload.get(field)
            if isinstance(deps, dict) and OLD in deps:
                failures.append(f"{rel}:{field}.orcel")
    if failures:
        raise RuntimeError("unscoped package dependency keys remain:\n" + "\n".join(failures))


def audit() -> None:
    core = json.loads((ROOT / "packages/orcel/package.json").read_text(encoding="utf-8"))
    if core.get("name") != NEW:
        raise RuntimeError("core package name was not migrated")
    if core.get("bin", {}).get("orcel") != "./bin/orcel.js":
        raise RuntimeError("CLI binary identity changed unexpectedly")
    if core.get("version") != "0.69.0":
        raise RuntimeError("bootstrap version changed unexpectedly")

    adapter = json.loads(
        (ROOT / "packages/orcel-buzz-acp-adapter/package.json").read_text(encoding="utf-8")
    )
    if adapter.get("name") != "@orcel/buzz-acp-adapter":
        raise RuntimeError("adapter package identity changed unexpectedly")
    adapter_deps = adapter.get("dependencies", {})
    if NEW not in adapter_deps or OLD in adapter_deps:
        raise RuntimeError("adapter core dependency was not migrated")

    package_name_source = (
        ROOT / "packages/orcel/src/internal/package-name.ts"
    ).read_text(encoding="utf-8")
    if f'ORCEL_PACKAGE_NAME = "{NEW}"' not in package_name_source:
        raise RuntimeError("central package-name constant was not migrated")

    allowlist = (ROOT / "scripts/assert-changeset-publish-packages.mjs").read_text(
        encoding="utf-8"
    )
    if NEW not in allowlist:
        raise RuntimeError("release publish allowlist was not migrated")

    assert_package_json_dependencies()

    failures: list[str] = []
    import_pattern = re.compile(
        r"(?:\bfrom\s+|\bimport\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)"
        r"[\"']orcel(?:[/\"'])"
    )
    quoted_subpath = re.compile(r"[\"']orcel/[^\"']+[\"']")
    workspace_dep = re.compile(r'"orcel"\s*:\s*"workspace:')
    for rel, text in read_active_texts():
        checks = (
            (import_pattern, "unscoped import"),
            (quoted_subpath, "unscoped quoted package subpath"),
            (workspace_dep, "unscoped workspace dependency"),
        )
        for pattern, label in checks:
            if pattern.search(text):
                failures.append(f"{rel}: {label}")
        if "@orcel/orcel/orcel" in text:
            failures.append(f"{rel}: duplicated scoped package path")
        if 'ORCEL_PACKAGE_NAME = "orcel"' in text or "ORCEL_PACKAGE_NAME = 'orcel'" in text:
            failures.append(f"{rel}: unscoped package-name constant")
        if "dependencies.orcel" in text or "dependencies?.orcel" in text:
            failures.append(f"{rel}: unscoped dependency property access")
        if "node_modules/orcel/" in text:
            failures.append(f"{rel}: unscoped node_modules path")

    if failures:
        preview = "\n".join(failures[:100])
        extra = len(failures) - min(len(failures), 100)
        if extra:
            preview += f"\n... and {extra} more"
        raise RuntimeError("npm-scope migration audit failed:\n" + preview)


if __name__ == "__main__":
    changed_files = migrate()
    audit()
    print(f"MIGRATION_CHANGED_FILES={len(changed_files)}")
    print("MIGRATION_AUDIT=PASS")
