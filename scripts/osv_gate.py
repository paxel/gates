"""Decides whether osv-scanner's findings stop a run.

osv-scanner runs once per repository with the licence allowlist and every package listed:

    osv-scanner scan source -r --all-packages --licenses="$(osv_gate.py --allowlist standard.toml)" \
        --format json --output-file osv.json .
    python3 osv_gate.py --results osv.json --root . --standard standard.toml [--strict]

What blocks:
- a known vulnerability (an unmaintained notice only with --strict, the weekly run);
- a dependency whose licence is not on the standard's allowlist. deps.dev, where osv-scanner
  takes licences from, has none for Pub; a Pub package osv-scanner reports as UNKNOWN is looked
  up on pub.dev for its locked version, and blocks unless pub.dev names its licences and every
  one of them is on the allowlist;
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
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

SKIP_DIRS = {".git", "target", "node_modules", "build", ".dart_tool", ".gates", "vendor"}

PUB_HOST = "https://pub.dev"
# pub.dev's licence tags that classify a licence rather than name one.
PUB_CLASSIFICATIONS = {"fsf-libre", "osi-approved"}
# Waits before the second and the third try of a pub.dev lookup that met a network error, a
# timeout, an HTTP 429 or an HTTP 5xx; after the last try the package blocks.
PUB_WAITS = (2.0, 4.0)


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


# A Pub lookup: the licences pub.dev names for one version, or the reason it names none.
PubLookup = Callable[[str, str], tuple[list[str], str]]


def pub_licences(name: str, version: str) -> tuple[list[str], str]:
    """The SPDX ids pub.dev's analysis tags the version with; an empty list with the reason
    when pub.dev gives none (no answer, or an obsolete version it no longer analyses)."""
    quoted = urllib.parse.quote(name, safe=""), urllib.parse.quote(version, safe="")
    path = "api/packages/{}/versions/{}/score".format(*quoted)
    for wait in (*PUB_WAITS, None):
        try:
            with urllib.request.urlopen(f"{PUB_HOST}/{path}", timeout=60) as response:  # noqa: S310 - fixed https host
                data = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as error:
            if wait is None or not (error.code == 429 or error.code >= 500):
                return [], f"no answer from pub.dev: {error}"
        except ValueError as error:
            return [], f"no answer from pub.dev: {error}"
        except OSError as error:
            if wait is None:
                return [], f"no answer from pub.dev: {error}"
        time.sleep(wait)
    tags = data.get("tags") if isinstance(data, dict) else None
    if not isinstance(tags, list):
        return [], "no tags from pub.dev"
    licences = [
        str(tag)[len("license:") :]
        for tag in tags
        if str(tag).startswith("license:") and str(tag)[len("license:") :] not in PUB_CLASSIFICATIONS
    ]
    return licences, "" if licences else "pub.dev names no licence for this version"


def pub_finding(
    info: dict[str, Any],
    label: str,
    allowed: set[str],
    lookup: PubLookup,
    cache: dict[tuple[str, str], tuple[list[str], str]],
) -> Finding | None:
    """None when pub.dev names the version's licences and every one is allowed."""
    key = (str(info.get("name") or ""), str(info.get("version") or ""))
    if key not in cache:
        cache[key] = lookup(*key)
    licences, reason = cache[key]
    if not licences:
        return Finding(True, "LICENCE", f"{label}: UNKNOWN, {reason}")
    outside = [lic for lic in licences if lic.lower() not in allowed]
    if outside:
        return Finding(True, "LICENCE", f"{label}: {', '.join(outside)} (pub.dev)")
    return None


def result_findings(
    results: dict[str, Any],
    strict: bool,
    own: set[str] | None = None,
    allow: Iterable[str] = (),
    lookup: PubLookup | None = None,
) -> list[Finding]:
    rows: list[Finding] = []
    look = lookup or pub_licences
    allowed = {a.lower() for a in allow}
    cache: dict[tuple[str, str], tuple[list[str], str]] = {}
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
            violations = [str(v) for v in package.get("license_violations") or []]
            if not violations or info.get("name") in (own or set()):
                continue
            if info.get("ecosystem") == "Pub" and violations == ["UNKNOWN"]:
                finding = pub_finding(info, f"{name} in {source}", allowed, look, cache)
                if finding:
                    rows.append(finding)
                continue
            rows.append(Finding(True, "LICENCE", f"{name} in {source}: {', '.join(violations)}"))
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
        rows = result_findings(results, args.strict, own_packages(root), allowlist(standard))
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
