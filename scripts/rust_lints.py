"""Checks that every crate of a repository carries the standard's Rust lint set (Q13).

    python3 rust_lints.py --root . --lints configs/rust/lints.toml

Each Cargo.toml with a [package] must deny (or forbid) every lint of the set, in its own
[lints] or, with `[lints] workspace = true`, in the [workspace.lints] of its workspace root.
Fuzz crates and build output are skipped.

Exit 0: every crate holds the set. Exit 1: a crate lacks a lint. Exit 2: a file cannot be read.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tomllib
from collections.abc import Sequence
from typing import Any

SKIP = {".git", "target", "fuzz", ".gates", "node_modules", "fixtures"}
STRICT = {"deny", "forbid"}


def load(path: pathlib.Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def level(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("level", ""))
    return str(value)


def required(lints_file: pathlib.Path) -> dict[str, set[str]]:
    data = load(lints_file).get("lints") or {}
    return {tool: set(table) for tool, table in data.items()}


def workspace_lints(manifest: pathlib.Path, root: pathlib.Path) -> dict[str, Any] | None:
    for parent in [manifest.parent, *manifest.parent.parents]:
        candidate = parent / "Cargo.toml"
        if candidate.exists():
            ws = load(candidate).get("workspace")
            if ws is not None:
                return dict(ws.get("lints") or {})
        if parent == root:
            break
    return None


def check(root: pathlib.Path, need: dict[str, set[str]]) -> list[str]:
    problems: list[str] = []
    for manifest in sorted(root.rglob("Cargo.toml")):
        rel = manifest.relative_to(root)
        if any(part in SKIP for part in rel.parts):
            continue
        data = load(manifest)
        if "package" not in data:
            continue
        lints = data.get("lints") or {}
        source = str(rel)
        if lints.get("workspace") is True:
            ws = workspace_lints(manifest, root)
            if ws is None:
                problems.append(
                    f"{rel}: [lints] workspace = true, but no workspace root has [workspace.lints]"
                )
                continue
            lints, source = ws, f"{rel} (workspace lints)"
        for tool, names in sorted(need.items()):
            table = lints.get(tool) or {}
            for name in sorted(names):
                if level(table.get(name)) not in STRICT:
                    problems.append(f"{source}: {tool}::{name} is not denied")
    return problems


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="rust_lints.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--lints", required=True)
    args = parser.parse_args(argv)
    try:
        problems = check(pathlib.Path(args.root).resolve(), required(pathlib.Path(args.lints)))
    except (OSError, ValueError) as error:
        print(f"cannot read a Cargo.toml or the lint set: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(f"LINT SET: {problem}")
    print(f"{len(problems)} lints missing")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
