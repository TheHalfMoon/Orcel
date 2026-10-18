#!/usr/bin/env python3
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate the implementation-readiness planning package.

Checks, with the standard library only:
  * donor_registry.json: unique ids, 40-hex pins, known strategies;
  * transplant_matrix.json: known donors, methods and owning tasks;
  * backlog/tasks.json: required fields, known dependencies, acyclic order,
    existing Orcel paths for every "existing_orcel" and "change" entry;
  * every relative Markdown link in the package (and the canonical files it
    edits) resolves.

Optional:
  --donors DIR   verify every donor path against local checkouts named
                 owner_repo (git required); print each object SHA.
  --write-objects  with --donors, record those SHAs in transplant_matrix.json.

Usage: python -I docs/orcel/implementation-readiness/tools/readiness_check.py [--donors DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
REPO = PKG.parents[2]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
TASK_FIELDS = [
    "id", "phase", "title", "status", "objective", "user_visible", "existing_orcel", "donor",
    "donor_files", "method", "orcel_files", "dependencies", "steps", "interfaces", "platforms",
    "security", "tests", "performance", "ci", "depends_on", "acceptance", "done", "rollback",
    "estimate", "authority_delta", "proposed_grain",
]
TEST_KINDS = ["positive", "negative", "recovery", "e2e"]
STATUSES = {"READY", "BLOCKED_ON_DEPENDENCY", "FOUNDER_DECISION_REQUIRED"}
EXTRA_DOCS = [
    "docs/orcel/README.md",
    "docs/orcel/EXECUTION_FRONTIER.md",
    "docs/orcel/ORCEL_MASTER_PLAN.md",
    "docs/orcel/IMPLEMENTATION_ROADMAP.md",
    "docs/canonical/PLANNING_INDEX.md",
    "docs/orcel/SOURCE_PERMISSIONS.md",
    "docs/orcel/UI_UX_AND_APP_SIZE_BUDGET.md",
    "docs/orcel/grants/2026-10-13-founder-source-authorization.md",
    "docs/orcel/grants/2026-10-18-founder-attestation.md",
]


def load(rel: str):
    return json.loads((PKG / rel).read_text(encoding="utf-8"))


def strip_note(path: str) -> str:
    """'a/b.rs (lines 1-2: note)' -> 'a/b.rs'."""
    return path.split(" (")[0].strip()


def is_checkable(path: str) -> bool:
    return bool(path) and "*" not in path and not path.startswith("-") and " " not in path


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.notes: list[str] = []

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def note(self, msg: str) -> None:
        self.notes.append(msg)


def check_registry(reg: dict, rep: Report) -> dict:
    vocab = set(reg["strategy_vocabulary"])
    donors: dict = {}
    for d in reg["donors"]:
        if d["id"] in donors:
            rep.err(f"registry: duplicate donor id {d['id']}")
        donors[d["id"]] = d
        if not SHA40.fullmatch(d["commit"]):
            rep.err(f"registry: {d['id']} commit is not 40-hex")
        for extra in d.get("previous_pins", []) + ([d["latest_inspected"]] if "latest_inspected" in d else []):
            if not SHA40.fullmatch(extra):
                rep.err(f"registry: {d['id']} has a malformed pin {extra}")
        if d["strategy"] not in vocab:
            rep.err(f"registry: {d['id']} strategy {d['strategy']} not in vocabulary")
        if not (PKG / d["blueprint"]).is_file():
            rep.err(f"registry: {d['id']} blueprint {d['blueprint']} missing")
    return donors


def check_backlog(backlog: dict, rep: Report) -> dict:
    tasks: dict = {}
    for t in backlog["tasks"]:
        for f in TASK_FIELDS:
            if f not in t:
                rep.err(f"backlog: {t.get('id', '?')} lacks field {f}")
        for k in TEST_KINDS:
            if k not in t.get("tests", {}):
                rep.err(f"backlog: {t.get('id', '?')} tests lack {k}")
        if t["id"] in tasks:
            rep.err(f"backlog: duplicate task {t['id']}")
        if t["status"] not in STATUSES:
            rep.err(f"backlog: {t['id']} unknown status {t['status']}")
        if not t["acceptance"]:
            rep.err(f"backlog: {t['id']} has no acceptance criteria")
        tasks[t["id"]] = t
    known = set(tasks) | {f["id"] for f in backlog["founder_decisions"]} | {
        e["id"] for e in backlog["external_dependencies"]
    }
    def ancestors(node: str, seen: set[str]) -> set[str]:
        for dep in tasks[node]["depends_on"]:
            if dep in tasks and dep not in seen:
                seen.add(dep)
                ancestors(dep, seen)
        return seen

    for t in tasks.values():
        for dep in t["depends_on"]:
            if dep not in known:
                rep.err(f"backlog: {t['id']} depends on unknown {dep}")
        for path in t["existing_orcel"]:
            p = strip_note(path)
            if is_checkable(p) and not (REPO / p).exists():
                rep.err(f"backlog: {t['id']} existing_orcel path missing: {p}")
        created_upstream = {
            strip_note(c) for a in ancestors(t["id"], set()) for c in tasks[a]["orcel_files"].get("create", [])
        }
        for path in t["orcel_files"].get("change", []):
            p = strip_note(path)
            if not is_checkable(p) or (REPO / p).exists() or p in created_upstream:
                continue
            if "after " in path:
                rep.note(f"backlog: {t['id']} changes {p}, which an external change creates ({path})")
                continue
            rep.err(f"backlog: {t['id']} change path missing and not created by a prerequisite: {p}")
    # Acyclic over task-to-task edges.
    state: dict[str, int] = {}

    def visit(node: str, stack: list[str]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            rep.err("backlog: dependency cycle " + " -> ".join(stack + [node]))
            return
        state[node] = 1
        for dep in tasks[node]["depends_on"]:
            if dep in tasks:
                visit(dep, stack + [node])
        state[node] = 2

    for node in tasks:
        visit(node, [])
    return tasks


def check_matrix(matrix: dict, donors: dict, tasks: dict, backlog: dict, rep: Report) -> None:
    vocab = {"COPY", "COPY_ADAPT", "WRAP", "COMPOSE", "PORT", "BUILD_NEW", "REFERENCE", "REJECT"}
    fds = {f["id"] for f in backlog["founder_decisions"]}
    seen = set()
    for r in matrix["rows"]:
        if r["id"] in seen:
            rep.err(f"matrix: duplicate row {r['id']}")
        seen.add(r["id"])
        if r["donor"] not in donors:
            rep.err(f"matrix: {r['id']} unknown donor {r['donor']}")
        if r["method"] not in vocab:
            rep.err(f"matrix: {r['id']} unknown method {r['method']}")
        if r["task"] != "-" and r["task"] not in tasks and r["task"] not in fds:
            rep.err(f"matrix: {r['id']} unknown task {r['task']}")
        if r["dest_state"] == "EXISTS" and not (REPO / r["dest"]).exists():
            rep.err(f"matrix: {r['id']} destination marked EXISTS is missing: {r['dest']}")


def git(checkout: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def check_donor_paths(donors_dir: Path, donors: dict, matrix: dict, tasks: dict, rep: Report, write: bool) -> None:
    def checkout_for(donor_id: str):
        d = donors[donor_id]
        co = donors_dir / d["repo"].replace("/", "_")
        if not (co / ".git").exists():
            return None, None
        head = git(co, "rev-parse", "HEAD")
        accepted = {d["commit"], d.get("latest_inspected", "")}
        return co, head if head in accepted else None

    for r in matrix["rows"]:
        co, head = checkout_for(r["donor"])
        if co is None:
            rep.note(f"matrix: {r['id']} no local checkout for {r['donor']} (verify remotely)")
            continue
        want = r.get("at", donors[r["donor"]]["commit"])
        if head is None or head != want:
            rep.note(f"matrix: {r['id']} local {r['donor']} HEAD is not {want[:12]}; path not verified")
            continue
        try:
            obj = git(co, "rev-parse", f"HEAD:{r['path']}")
        except subprocess.CalledProcessError:
            rep.err(f"matrix: {r['id']} path absent at {want[:12]}: {r['path']}")
            continue
        r["object"] = obj
        rep.note(f"matrix: {r['id']} {obj} {r['path']}")
    if write:
        (PKG / "transplant_matrix.json").write_text(
            json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )
    for t in tasks.values():
        if not t["donor"]:
            continue
        donor_id = t["donor"].split("@")[0]
        if donor_id not in donors:
            rep.err(f"backlog: {t['id']} unknown donor {donor_id}")
            continue
        co, head = checkout_for(donor_id)
        if co is None or head is None:
            continue
        for path in t["donor_files"]:
            p = strip_note(path)
            if is_checkable(p):
                try:
                    git(co, "rev-parse", f"HEAD:{p}")
                except subprocess.CalledProcessError:
                    rep.err(f"backlog: {t['id']} donor path absent in {donor_id}: {p}")


LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def check_links(rep: Report) -> None:
    files = sorted(PKG.rglob("*.md")) + [REPO / p for p in EXTRA_DOCS]
    for md in files:
        if not md.is_file():
            continue
        for target in LINK.findall(md.read_text(encoding="utf-8")):
            if re.match(r"^[a-z]+:", target) or target.startswith("#"):
                continue
            path = target.split("#")[0]
            if path and not (md.parent / path).resolve().exists():
                rep.err(f"link: {md.relative_to(REPO)} -> {target} does not resolve")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--donors", type=Path)
    ap.add_argument("--write-objects", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if args.write_objects and not args.donors:
        ap.error("--write-objects requires --donors")
    rep = Report()
    reg = load("donor_registry.json")
    matrix = load("transplant_matrix.json")
    backlog = load("backlog/tasks.json")
    donors = check_registry(reg, rep)
    tasks = check_backlog(backlog, rep)
    check_matrix(matrix, donors, tasks, backlog, rep)
    if args.donors:
        check_donor_paths(args.donors, donors, matrix, tasks, rep, args.write_objects)
    check_links(rep)
    if args.verbose:
        for n in rep.notes:
            print("note:", n)
    for e in rep.errors:
        print("error:", e)
    print(
        f"readiness: {len(donors)} donors, {len(matrix['rows'])} matrix rows, {len(tasks)} tasks, "
        f"{len(backlog['founder_decisions'])} founder decisions; {len(rep.errors)} errors"
    )
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
