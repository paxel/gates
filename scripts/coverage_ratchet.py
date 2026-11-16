"""The coverage ratchet: line coverage of each measured part may only go up.

coverage-floors.toml at the repository root names every measured part, its lcov file and
its floor:

    [[parts]]
    name = "core"
    lcov = "coverage/core.lcov"
    floor = 92.12
    exclude = ["src/infrastructure/beeper.rs"]   # optional, files left out of the measure

    python3 coverage_ratchet.py --floors coverage-floors.toml [--check]

A part below its floor fails. A part above it raises the floor to the measured value minus
0.1 and rewrites its badge in .github/badges/coverage-<name>.json, so the floor follows
reality and the file is committed with the change that earned it. With --check (CI) the
floors are only verified, never written. A part whose lcov is missing or measures no line
fails: a ratchet must not pass on nothing.

Exit 0: every part holds. Exit 1: a part is below its floor or measured nothing. Exit 2: the
floors file or an lcov file cannot be read.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import pathlib
import re
import sys
import tomllib
from collections.abc import Sequence
from typing import Any

MARGIN = 0.10


def inside(root: pathlib.Path, path: str) -> pathlib.Path:
    """root/path for a path named in the floors file; it must not leave the repository."""
    joined = os.path.normpath(os.path.join(root, path))
    if os.path.commonpath([str(root), joined]) != str(root):
        raise ValueError(f"{path} is outside the repository")
    return pathlib.Path(joined)


def source(path: str, root: pathlib.Path) -> str:
    """A source file of an lcov record as the exclude patterns name it: relative to the root.

    Nothing is looked up on disk; the path comes from the report.
    """
    path = os.path.normpath(path)
    if os.path.isabs(path) and os.path.commonpath([str(root), path]) == str(root):
        return os.path.relpath(path, root)
    return path


def measure(lcov: pathlib.Path, root: pathlib.Path, exclude: Sequence[str]) -> tuple[int, int]:
    """(lines found, lines hit) over every source file not excluded."""
    found = hit = 0
    current: str | None = None
    for raw in lcov.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = source(line[3:], root)
        elif line.startswith("LF:") and current is not None and not excluded(current, exclude):
            found += int(line[3:])
        elif line.startswith("LH:") and current is not None and not excluded(current, exclude):
            hit += int(line[3:])
        elif line == "end_of_record":
            current = None
    return found, hit


def excluded(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) or path.endswith("/" + p) or path == p for p in patterns)


def colour(value: float) -> str:
    return "brightgreen" if value >= 90 else "green" if value >= 75 else "yellow" if value >= 60 else "red"


def write_badge(badges: pathlib.Path, name: str, floor: float) -> None:
    badges.mkdir(parents=True, exist_ok=True)
    label = "coverage" if name in ("", "all") else f"coverage {name}"
    body = {"schemaVersion": 1, "label": label, "message": f"{floor:.2f}%", "color": colour(floor)}
    (badges / f"coverage-{name}.json").write_text(json.dumps(body) + "\n", encoding="utf-8")


def raise_floor(text: str, name: str, new: float) -> str:
    """The floors file with the floor of part `name` replaced; everything else untouched."""
    blocks = re.split(r"(?m)^(?=\[\[parts\]\])", text)
    for i, block in enumerate(blocks):
        if re.search(rf'(?m)^name\s*=\s*"{re.escape(name)}"\s*$', block):
            blocks[i] = re.sub(r"(?m)^floor\s*=\s*[0-9.]+", f"floor = {new:.2f}", block, count=1)
    return "".join(blocks)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="coverage_ratchet.py")
    parser.add_argument("--floors", default="coverage-floors.toml")
    parser.add_argument("--badges", default=".github/badges")
    parser.add_argument("--check", action="store_true", help="verify only, never write (CI)")
    parser.add_argument("--part", action="append", default=[], help="only this part (repeatable)")
    args = parser.parse_args(argv)
    floors_path = pathlib.Path(args.floors)
    root = floors_path.resolve().parent
    try:
        text = floors_path.read_text(encoding="utf-8")
        parts: list[dict[str, Any]] = tomllib.loads(text).get("parts") or []
    except (OSError, ValueError) as error:
        print(f"coverage: cannot read {floors_path}: {error}", file=sys.stderr)
        return 2
    if args.part:
        unknown = set(args.part) - {str(p.get("name")) for p in parts}
        if unknown:
            print(f"coverage: {floors_path} names no part {', '.join(sorted(unknown))}", file=sys.stderr)
            return 1
        parts = [p for p in parts if str(p.get("name")) in args.part]
    if not parts:
        print(f"coverage: {floors_path} names no part", file=sys.stderr)
        return 1
    failed = False
    for part in parts:
        name, floor = str(part["name"]), float(part["floor"])
        try:
            if not re.fullmatch(r"[\w.-]+", name):
                raise ValueError(f"the part's name {name!r} is no file name for its badge")
            found, hit = measure(inside(root, str(part["lcov"])), root, list(part.get("exclude") or []))
        except (OSError, ValueError) as error:
            print(f"coverage {name}: cannot read {part['lcov']}: {error}", file=sys.stderr)
            return 2
        if found == 0:
            print(f"coverage {name}: {part['lcov']} measures no line")
            failed = True
            continue
        value = round(100.0 * hit / found, 2)
        if value < floor:
            print(
                f"coverage {name}: {value:.2f}% is below the floor of {floor:.2f}%; the ratchet only goes up"
            )
            failed = True
            continue
        raised = round(value - MARGIN, 2)
        if raised > floor and not args.check:
            text = raise_floor(text, name, raised)
            write_badge(pathlib.Path(args.badges), name, raised)
            print(
                f"coverage {name}: {value:.2f}%, floor raised from {floor:.2f}% to {raised:.2f}%;"
                " commit the floors and the badge"
            )
        else:
            print(f"coverage {name}: {value:.2f}% (floor {floor:.2f}%)")
    if not args.check:
        floors_path.write_text(text, encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
