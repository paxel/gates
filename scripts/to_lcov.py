"""Converts a coverage report into the lcov the ratchet reads.

    python3 to_lcov.py go cover.out > part.lcov        # go test -coverprofile
    python3 to_lcov.py jacoco jacoco.xml > part.lcov   # JaCoCo XML report

Go counts statements and JaCoCo counts lines; either way LF is what can be covered and LH
what was, per source file, which is all coverage_ratchet.py needs.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET  # noqa: S405 - reads the build's own JaCoCo report
from collections import defaultdict
from collections.abc import Sequence


def from_go(text: str) -> dict[str, tuple[int, int]]:
    seen: dict[tuple[str, str], tuple[int, bool]] = {}
    for line in text.splitlines():
        if not line or line.startswith("mode:"):
            continue
        block, statements, count = line.rsplit(" ", 2)
        path = block.rsplit(":", 1)[0]
        key = (path, block)
        covered = int(count) > 0 or (key in seen and seen[key][1])
        seen[key] = (int(statements), covered)
    files: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for (path, _), (statements, covered) in seen.items():
        files[path][0] += statements
        if covered:
            files[path][1] += statements
    return {p: (v[0], v[1]) for p, v in files.items()}


def from_jacoco(text: str) -> dict[str, tuple[int, int]]:
    root = ET.fromstring(text)  # noqa: S314 - the build's own report, not untrusted input
    files: dict[str, tuple[int, int]] = {}
    for package in root.iter("package"):
        for source in package.iter("sourcefile"):
            for counter in source.iter("counter"):
                if counter.get("type") == "LINE":
                    missed, covered = int(counter.get("missed", 0)), int(counter.get("covered", 0))
                    files[f'{package.get("name")}/{source.get("name")}'] = (missed + covered, covered)
    return files


def lcov(files: dict[str, tuple[int, int]]) -> str:
    return "".join(f"SF:{p}\nLF:{lf}\nLH:{lh}\nend_of_record\n" for p, (lf, lh) in sorted(files.items()))


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("go", "jacoco"):
        print("usage: to_lcov.py go|jacoco <report>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as f:
            text = f.read()
        files = from_go(text) if argv[0] == "go" else from_jacoco(text)
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(lcov(files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
