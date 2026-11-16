"""Fetches a project's open SonarQube Cloud findings for alerts_gate.py.

    python3 sonar_fetch.py --properties sonar-project.properties --branch summer --out sonar.jsonl
    python3 sonar_fetch.py --properties sonar-project.properties --branch summer --pull-request 12 \\
        --out sonar.jsonl

Reads sonar.projectKey from the properties file and writes every open issue and every security
hotspot to review, one JSON object per line: those of the branch, those a pull request adds,
or both. SonarQube Cloud's quality gate looks at new code only; this is the whole list.

A public project is read without a token; a private one needs SONAR_TOKEN in the environment.

Exit 0: the list is written. Exit 2: the properties name no project, or SonarQube Cloud cannot
be read; a gate that could not read the findings must not pass.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

HOST = "https://sonarcloud.io"
PAGE = 500
# SonarQube Cloud returns at most this many results of one search.
LIMIT = 10000

Get = Callable[[str, dict[str, str]], dict[str, Any]]


def project_key(properties: str) -> str:
    for raw in properties.splitlines():
        name, _, value = raw.partition("=")
        if name.strip() == "sonar.projectKey" and value.strip():
            return value.strip()
    raise ValueError("no sonar.projectKey in the properties")


def fetch(path: str, params: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(f"{HOST}/{path}?{urllib.parse.urlencode(params)}")  # noqa: S310 - fixed https host
    token = os.environ.get("SONAR_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https host
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a JSON object")
    return data


def search(get: Get, path: str, params: dict[str, str], items: str) -> list[dict[str, Any]]:
    """Every result of one search, page by page."""
    found: list[dict[str, Any]] = []
    page = 1
    while True:
        data = get(path, {**params, "ps": str(PAGE), "p": str(page)})
        batch = data.get(items)
        total = (data.get("paging") or {}).get("total")
        if not isinstance(batch, list) or not isinstance(total, int):
            raise ValueError(f"{path}: no {items} or no total in the answer")
        if total > LIMIT:
            raise ValueError(f"{path}: {total} results, more than the {LIMIT} that can be read")
        found += batch
        if len(found) >= total or not batch:
            return found
        page += 1


def findings(get: Get, project: str, where: dict[str, str]) -> list[dict[str, Any]]:
    """The open issues and the hotspots to review of a branch or a pull request."""
    issues = search(
        get, "api/issues/search", {"componentKeys": project, "resolved": "false", **where}, "issues"
    )
    hotspots = search(
        get, "api/hotspots/search", {"projectKey": project, "status": "TO_REVIEW", **where}, "hotspots"
    )
    # alerts_gate.py takes the file from the component, "<project>:<path>".
    return [{**finding, "project": project} for finding in issues + hotspots]


def main(argv: Sequence[str], get: Get = fetch) -> int:
    parser = argparse.ArgumentParser(prog="sonar_fetch.py")
    parser.add_argument("--properties", required=True)
    parser.add_argument("--branch")
    parser.add_argument("--pull-request")
    parser.add_argument("--out", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    scopes = [{"branch": args.branch}] if args.branch else []
    if args.pull_request:
        scopes.append({"pullRequest": args.pull_request})
    if not scopes:
        print("sonar: name a --branch, a --pull-request or both", file=sys.stderr)
        return 2
    try:
        project = project_key(pathlib.Path(args.properties).read_text(encoding="utf-8"))
        found = [finding for where in scopes for finding in findings(get, project, where)]
        text = "".join(json.dumps(finding) + "\n" for finding in found)
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(f"sonar: cannot read the findings: {error}", file=sys.stderr)
        return 2
    print(f"{len(found)} open SonarQube Cloud findings of {project}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
