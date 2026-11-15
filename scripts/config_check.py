"""Checks that a stack's lint and build config holds the standard's strict settings (Q14).

    python3 config_check.py --stack dart --dir . --configs .gates/configs

configs/<stack>/required.toml lists what must be there:

    [[require]]
    files = ["analysis_options.yaml"]          # the first one that exists is read
    patterns = ['strict-casts:\\s*true']       # each must match somewhere in it
    why = "strict analysis (Q14)"

Exit 0: every requirement holds. Exit 1: a file is missing or a setting is not there. Exit 2:
the requirements cannot be read.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tomllib
from collections.abc import Sequence
from typing import Any


def check(directory: pathlib.Path, requirements: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    for req in requirements:
        names = [str(n) for n in req.get("files") or []]
        found = next((directory / n for n in names if (directory / n).is_file()), None)
        why = str(req.get("why", ""))
        if found is None:
            problems.append(f"{directory}: none of {', '.join(names)} exists ({why})")
            continue
        text = found.read_text(encoding="utf-8", errors="replace")
        for pattern in req.get("patterns") or []:
            if not re.search(str(pattern), text, re.MULTILINE):
                problems.append(f"{found}: no match for {pattern!r} ({why})")
    return problems


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="config_check.py")
    parser.add_argument("--stack", required=True)
    parser.add_argument("--dir", action="append", default=[])
    parser.add_argument("--configs", required=True)
    args = parser.parse_args(argv)
    try:
        with (pathlib.Path(args.configs) / args.stack / "required.toml").open("rb") as f:
            requirements = tomllib.load(f).get("require") or []
    except (OSError, ValueError) as error:
        print(f"cannot read the {args.stack} requirements: {error}", file=sys.stderr)
        return 2
    problems: list[str] = []
    for directory in args.dir or ["."]:
        problems += check(pathlib.Path(directory), requirements)
    for problem in problems:
        print(f"CONFIG: {problem}")
    print(f"{len(problems)} config problems ({args.stack})")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
