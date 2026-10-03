#!/usr/bin/env python3
"""Migrate Orcel's published core npm identity to @orcel/orcel.

This helper is intentionally narrow: it changes npm package identity references while
preserving product branding, the `orcel` CLI binary, `.orcel` state paths, `/orcel`
HTTP routes, route inputs such as `orcel/support`, historical changelogs/research,
provenance, and external compatibility identifiers.

GitHub workflow files are intentionally excluded from the bulk write because the
branch-scoped Actions token cannot update workflow definitions. Required workflow
package-reference edits are applied separately through the repository connector and
qualified on the final PR head.
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
    ".github/workflows/",
    ".orcel-migration/",
    "research/",
)
SKIP_EXACT = {
    ".github/scripts/migrate-orcel-npm-scope.py",
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
DOC_SUFFIXES = {".md", ".mdx"}
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


def exported_package_subpaths() -> tuple[str, ...]:
    payload = json.loads((ROOT / "packages/orcel/package.json").read_text(encoding="utf-8"))
    exports = payload.get("exports", {})
    if not isinstance(exports, dict):
        return ()
    values = [
        key[2:]
        for key in exports
        if key.startswith("./") and "*" not in key and key != "."
    ]
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def scope_package_specifier(specifier: str) -> str:
    if specifier == OLD:
        return NEW
    if specifier.startswith(f"{OLD}/"):
        return f"{NEW}/{specifier[len(OLD) + 1:]}"
    return specifier


def replace_import_specifiers(text: str) -> str:
    patterns = (
        re.compile(r"(\bfrom\s+)([\"'])(orcel(?:/[^\"']+)?)(\2)"),
        re.compile(r"(\bimport\s+)([\"'])(orcel(?:/[^\"']+)?)(\2)"),
        re.compile(r"(\bimport\s*\(\s*)([\"'])(orcel(?:/[^\"']+)?)(\2)"),
        re.compile(r"(\brequire\s*\(\s*)([\"'])(orcel(?:/[^\"']+)?)(\2)"),
    )

    def replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}{scope_package_specifier(match.group(3))}{match.group(4)}"

    for pattern in patterns:
        text = pattern.sub(replace, text)

    escaped_prefixes = (
        'from \\"orcel',
        "from \\'orcel",
        'import \\"orcel',
        "import \\'orcel",
        'import(\\"orcel',
        "import(\\'orcel",
        'require(\\"orcel',
        "require(\\'orcel",
    )
    for prefix in escaped_prefixes:
        replacement = prefix.replace("orcel", NEW, 1)
        text = text.replace(prefix, replacement)
    return text


def replace_workspace_dependency_keys(text: str) -> str:
    text = re.sub(
        r'"orcel"(\s*:\s*"workspace:[^"]*")',
        rf'"{NEW}"\1',
        text,
    )
    text = re.sub(
        r'\\"orcel\\"(\s*:\s*\\"workspace:[^\\"]*\\")',
        rf'\\"{NEW}\\"\1',
        text,
    )
    return text


def replace_inline_dependency_object_keys(text: str) -> str:
    for field in DEPENDENCY_FIELDS:
        pattern = re.compile(
            rf"({field}\s*:\s*\{{\s*)orcel(\s*:)",
            flags=re.MULTILINE,
        )
        text = pattern.sub(rf'\1"{NEW}"\2', text)
    return text


def replace_package_identity_guards(text: str) -> str:
    text = re.sub(
        r'(ORCEL_PACKAGE_NAME\s*=\s*)([\"\'])orcel\2',
        rf'\1\2{NEW}\2',
        text,
    )

    for lhs in ("source", "specifier", "moduleSpecifier", "request", "packageName"):
        text = text.replace(f'{lhs} === "orcel"', f'{lhs} === "{NEW}"')
        text = text.replace(f"{lhs} === 'orcel'", f"{lhs} === '{NEW}'")
        text = text.replace(
            f'{lhs}.startsWith("orcel/")', f'{lhs}.startsWith("{NEW}/")'
        )
        text = text.replace(
            f"{lhs}.startsWith('orcel/')", f"{lhs}.startsWith('{NEW}/')"
        )

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

    text = text.replace(
        'join(root, "node_modules", "orcel")',
        'join(root, "node_modules", "@orcel", "orcel")',
    )
    return text


def replace_documented_export_paths(rel: str, text: str, subpaths: tuple[str, ...]) -> str:
    path = Path(rel)
    is_doc = path.suffix.lower() in DOC_SUFFIXES or path.name in {"README", "README.md"}
    if not is_doc:
        return text
    for subpath in subpaths:
        old = f"orcel/{subpath}"
        new = f"{NEW}/{subpath}"
        pattern = re.compile(rf"(?<![A-Za-z0-9@._-]){re.escape(old)}(?![A-Za-z0-9._/-])")
        text = pattern.sub(new, text)
    return text


def migrate_text(rel: str, text: str, subpaths: tuple[str, ...]) -> str:
    original_route_count = public_route_count(text)
    original_state_count = text.count(".orcel/")

    if rel == "packages/orcel/package.json":
        text = text.replace('"name": "orcel"', f'"name": "{NEW}"', 1)

    text = replace_workspace_dependency_keys(text)
    text = replace_inline_dependency_object_keys(text)
    text = replace_import_specifiers(text)
    text = replace_package_identity_guards(text)
    text = replace_installation_surface(text)
    text = replace_documented_export_paths(rel, text, subpaths)

    if rel == "scripts/assert-changeset-publish-packages.mjs":
        text = text.replace('"orcel"', f'"{NEW}"')
        text = text.replace("'orcel'", f"'{NEW}'")

    if public_route_count(text) != original_route_count:
        raise RuntimeError(f"public route surface changed unexpectedly: {rel}")
    if text.count(".orcel/") != original_state_count:
        raise RuntimeError(f"local state path surface changed unexpectedly: {rel}")
    return text


def migrate() -> list[str]:
    subpaths = exported_package_subpaths()
    changed: list[str] = []
    for rel in tracked_files():
        if not is_active_text(rel):
            continue
        path = ROOT / rel
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        updated = migrate_text(rel, text, subpaths)
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

    route_test = (
        ROOT / "packages/orcel/src/shared/public-route-prefix.test.ts"
    ).read_text(encoding="utf-8")
    if 'normalizePublicRoutePrefix("orcel/support")' not in route_test:
        raise RuntimeError("slashless route-normalization input changed unexpectedly")

    assert_package_json_dependencies()

    failures: list[str] = []
    import_pattern = re.compile(
        r"(?:\bfrom\s+|\bimport\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)"
        r"[\"']orcel(?:[/\"'])"
    )
    escaped_import_pattern = re.compile(
        r"(?:\bfrom\s+|\bimport\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)"
        r"\\[\"']orcel(?:[/\\])"
    )
    workspace_dep = re.compile(r'"orcel"\s*:\s*"workspace:')
    for rel, text in read_active_texts():
        checks = (
            (import_pattern, "unscoped import"),
            (escaped_import_pattern, "unscoped escaped import"),
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
