"""Checks what a repository without app code holds (Q10).

    python3 content_check.py scoop  bucket/        # every manifest is valid
    python3 content_check.py skills skills/        # every skill has its frontmatter
    python3 content_check.py site   repo/ archive/ # every local link resolves

Formulas are checked by `brew style` and `brew audit` in content.yml, not here.

scoop:  each *.json parses and has version, description, homepage, license, and either url
        with hash or architecture entries that each have url and hash; a hash is 64 hex digits.
skills: each <dir>/SKILL.md starts with --- frontmatter holding name (equal to the directory)
        and description.
site:   each href and src in an .html file that is not a URL, an anchor or mailto points at a
        file that exists.

Exit 0: everything holds. Exit 1: a problem. Exit 2: bad arguments or nothing to check.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections.abc import Sequence
from html.parser import HTMLParser
from typing import Any

HASH = re.compile(r"^(sha256:)?[0-9a-fA-F]{64}$")


def scoop(directory: pathlib.Path) -> tuple[int, list[str]]:
    problems: list[str] = []
    files = sorted(directory.glob("*.json"))
    for path in files:
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as error:
            problems.append(f"{path}: not JSON: {error}")
            continue
        for key in ("version", "description", "homepage", "license"):
            if not data.get(key):
                problems.append(f"{path}: no {key}")
        targets = [data] if "url" in data else list((data.get("architecture") or {}).values())
        if not targets:
            problems.append(f"{path}: neither url nor architecture")
        for target in targets:
            urls, hashes = target.get("url"), target.get("hash")
            urls = urls if isinstance(urls, list) else [urls]
            hashes = hashes if isinstance(hashes, list) else [hashes]
            if not all(urls) or len(urls) != len(hashes):
                problems.append(f"{path}: every url needs its hash")
            for value in hashes:
                if not isinstance(value, str) or not HASH.match(value):
                    problems.append(f"{path}: hash {value!r} is not a sha256")
    return len(files), problems


def skills(directory: pathlib.Path) -> tuple[int, list[str]]:
    problems: list[str] = []
    dirs = sorted(p for p in directory.iterdir() if p.is_dir())
    for skill in dirs:
        doc = skill / "SKILL.md"
        if not doc.is_file():
            problems.append(f"{skill}: no SKILL.md")
            continue
        text = doc.read_text(encoding="utf-8")
        match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
        if not match:
            problems.append(f"{doc}: no --- frontmatter")
            continue
        fields = dict(
            (k.strip(), v.strip())
            for k, _, v in (line.partition(":") for line in match.group(1).splitlines())
            if k and not k.startswith(" ")
        )
        if fields.get("name") != skill.name:
            problems.append(f"{doc}: name {fields.get('name')!r} is not the directory {skill.name!r}")
        if not fields.get("description"):
            problems.append(f"{doc}: no description")
    return len(dirs), problems


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.targets.append(value)


def site(directory: pathlib.Path) -> tuple[int, list[str]]:
    problems: list[str] = []
    pages = sorted(directory.rglob("*.html"))
    for page in pages:
        parser = Links()
        parser.feed(page.read_text(encoding="utf-8", errors="replace"))
        for target in parser.targets:
            if re.match(r"^([a-z][a-z0-9+.-]*:|#|//)", target, re.IGNORECASE):
                continue
            path = target.split("#", 1)[0].split("?", 1)[0]
            if not path:
                continue
            resolved = (page.parent / path).resolve()
            if resolved.is_dir():
                resolved = resolved / "index.html"
            if not resolved.exists():
                problems.append(f"{page}: {target} does not exist")
    return len(pages), problems


KINDS = {"scoop": scoop, "skills": skills, "site": site}


def main(argv: Sequence[str]) -> int:
    if len(argv) < 2 or argv[0] not in KINDS:
        print(f"usage: content_check.py {'|'.join(KINDS)} <dir>...", file=sys.stderr)
        return 2
    checked, problems = 0, []
    for directory in argv[1:]:
        count, found = KINDS[argv[0]](pathlib.Path(directory))
        checked += count
        problems += found
    for problem in problems:
        print(f"CONTENT: {problem}")
    print(f"{checked} checked, {len(problems)} problems ({argv[0]})")
    if checked == 0:
        print("nothing to check: a content check must not pass on nothing", file=sys.stderr)
        return 2
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
