"""Decides whether osv-scanner's findings stop a run.

osv-scanner runs once per repository with the licence allowlist and every package listed:

    osv-scanner scan source -r --all-packages --licenses="$(osv_gate.py --allowlist standard.toml)" \
        --format json --output-file osv.json .
    python3 osv_gate.py --results osv.json --root . --standard standard.toml [--strict]

What blocks:
- a known vulnerability (an unmaintained notice only with --strict, the weekly run);
- a dependency whose licence is not on the standard's allowlist;
- an [[IgnoredVulns]] entry in an osv-scanner.toml without a reason, without an ignoreUntil
  date or with a date that has passed, and a [[PackageOverrides]] entry without a reason,
  without an effectiveUntil date or with a date that has passed;
- a manifest (Cargo.toml, pubspec.yaml, ...) whose lockfile osv-scanner did not read, so a
  stack cannot pass with nothing scanned.

Exit 0: nothing blocks. Exit 1: something blocks. Exit 2: the results, the standard or a
config cannot be read.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

SKIP_DIRS = {".git", "target", "node_modules", "build", ".dart_tool", ".gates", "vendor", "fuzz"}


@dataclass(frozen=True)
class Finding:
    blocks: bool
    kind: str
    text: str


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def allowlist(standard: dict[str, Any]) -> list[str]:
    """The allowlist as osv-scanner takes it: bare SPDX identifiers only. An exception such as
    "Apache-2.0 WITH LLVM-exception" only adds permissions, so it is covered by its licence."""
    allow: list[str] = []
    for entry in standard.get("licences", {}).get("allow", []):
        bare = str(entry).split(" WITH ")[0].strip()
        if bare not in allow:
            allow.append(bare)
    return allow


def unmaintained(vuln: dict[str, Any]) -> bool:
    """True when every affected entry is an informational unmaintained notice."""
    affected = vuln.get("affected") or []
    if not affected:
        return False
    return all(
        (entry.get("database_specific") or {}).get("informational") == "unmaintained" for entry in affected
    )


def scanned_sources(results: dict[str, Any]) -> set[str]:
    return {str((r.get("source") or {}).get("path", "")) for r in results.get("results") or []}


def own_packages(root: pathlib.Path) -> set[str]:
    """Names of the repository's own packages; deps.dev knows no licence for them."""
    names: set[str] = set()
    for path in walk(root):
        try:
            if path.name in ("Cargo.toml", "pyproject.toml"):
                data = load_toml(path)
                for table in ("package", "project"):
                    name = (data.get(table) or {}).get("name")
                    if name:
                        names.add(str(name))
            elif path.name == "package.json":
                name = json.loads(path.read_text(encoding="utf-8")).get("name")
                if name:
                    names.add(str(name))
            elif path.name == "pubspec.yaml":
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("name:"):
                        names.add(line.split(":", 1)[1].strip())
                        break
        except (OSError, ValueError):
            continue
    return names


def result_findings(results: dict[str, Any], strict: bool, own: set[str] | None = None) -> list[Finding]:
    rows: list[Finding] = []
    for result in results.get("results") or []:
        source = (result.get("source") or {}).get("path", "?")
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            name = f"{info.get('name') or '?'} {info.get('version') or '?'}"
            for vuln in package.get("vulnerabilities") or []:
                notice = unmaintained(vuln)
                rows.append(
                    Finding(
                        strict or not notice,
                        "UNMAINTAINED" if notice else "VULNERABILITY",
                        f"{vuln.get('id', '?')} {name} in {source}: {vuln.get('summary', '')}",
                    )
                )
            violations = package.get("license_violations") or []
            if violations and info.get("name") not in (own or set()):
                rows.append(
                    Finding(True, "LICENCE", f"{name} in {source}: {', '.join(map(str, violations))}")
                )
    return rows


def walk(root: pathlib.Path, exclude: Iterable[str] = ()) -> Iterable[pathlib.Path]:
    skip = SKIP_DIRS | set(exclude)
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in skip for part in rel.parts):
            continue
        yield path


def config_findings(root: pathlib.Path, today: datetime.date, exclude: Iterable[str] = ()) -> list[Finding]:
    rows: list[Finding] = []
    for path in walk(root, exclude):
        if path.name != "osv-scanner.toml":
            continue
        rel = path.relative_to(root)
        config = load_toml(path)
        for entry in config.get("IgnoredVulns") or []:
            rows += entry_findings(rel, f"IgnoredVulns {entry.get('id', '?')}", entry, "ignoreUntil", today)
        for entry in config.get("PackageOverrides") or []:
            label = f"PackageOverrides {entry.get('name', '?')} {entry.get('ecosystem', '')}".strip()
            rows += entry_findings(rel, label, entry, "effectiveUntil", today)
    return rows


def as_date(value: Any) -> datetime.date | None:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    return None


def entry_findings(
    rel: pathlib.Path, label: str, entry: dict[str, Any], date_key: str, today: datetime.date
) -> list[Finding]:
    problems = []
    if not str(entry.get("reason") or "").strip():
        problems.append("no reason")
    until = as_date(entry.get(date_key))
    if until is None:
        problems.append(f"no {date_key} date")
    elif until < today:
        problems.append(f"{date_key} {until} has passed")
    if problems:
        return [Finding(True, "BAD ENTRY", f"{rel}: {label}: {', '.join(problems)}")]
    return [Finding(False, "accepted", f"{rel}: {label} until {until}")]


# osv-scanner-action runs in a container with the workspace mounted here; its paths are
# mapped back onto the runner's workspace before they are compared.
CONTAINER_WORKSPACE = "/github/workspace/"


def normal(source: str) -> pathlib.Path:
    if source.startswith(CONTAINER_WORKSPACE):
        source = source[len(CONTAINER_WORKSPACE) :]
    return pathlib.Path(source).resolve()


def lockfile_findings(
    root: pathlib.Path, standard: dict[str, Any], sources: set[str], exclude: Iterable[str] = ()
) -> list[Finding]:
    """A manifest whose lockfile (beside it or in a parent, for workspaces) was not read."""
    rows: list[Finding] = []
    scanned = {normal(s) for s in sources if s}
    for stack in standard.get("stacks") or []:
        manifests = set(stack.get("manifests") or [])
        lockfiles = list(stack.get("lockfiles") or [])
        for path in walk(root, exclude):
            if path.name not in manifests:
                continue
            found = None
            for parent in [path.parent, *path.parent.parents]:
                for name in lockfiles:
                    candidate = (parent / name).resolve()
                    if candidate in scanned:
                        found = candidate
                        break
                if found or parent == root:
                    break
            rel = path.relative_to(root)
            if found is None:
                rows.append(
                    Finding(
                        True,
                        "NOT SCANNED",
                        f"{rel}: no {' or '.join(lockfiles)} was read by osv-scanner ({stack['id']})",
                    )
                )
    return rows


def main(argv: Sequence[str], today: datetime.date | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osv_gate.py")
    parser.add_argument("--allowlist", metavar="STANDARD", help="print the licence allowlist and exit")
    parser.add_argument("--results")
    parser.add_argument("--root", default=".")
    parser.add_argument("--standard")
    parser.add_argument("--strict", action="store_true", help="unmaintained notices block too")
    parser.add_argument(
        "--exclude", action="append", default=[], help="a directory name left out of the scan"
    )
    args = parser.parse_args(argv)
    try:
        if args.allowlist:
            print(",".join(allowlist(load_toml(pathlib.Path(args.allowlist)))))
            return 0
        if not args.results or not args.standard:
            parser.print_usage(sys.stderr)
            return 2
        standard = load_toml(pathlib.Path(args.standard))
        with open(args.results, encoding="utf-8") as f:
            results = json.load(f)
        root = pathlib.Path(args.root).resolve()
        day = today or datetime.date.today()
        rows = result_findings(results, args.strict, own_packages(root))
        rows += config_findings(root, day, args.exclude)
        rows += lockfile_findings(root, standard, scanned_sources(results), args.exclude)
    except (OSError, ValueError) as error:
        print(f"cannot read the results, the standard or a config: {error}", file=sys.stderr)
        return 2
    blocking = sum(1 for r in rows if r.blocks)
    for row in rows:
        print(f"{row.kind if row.blocks else row.kind + ' (reported only)'}: {row.text}")
    print(f"{len(rows)} findings, {blocking} of them blocking")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
