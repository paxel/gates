"""The weekly audit: every active repository against standard.toml (Q16).

    GH_TOKEN=<audit token> python3 scripts/audit/audit.py --out site [--issues]

Lists the owner's repositories, keeps the active ones (no fork, not archived, a commit this
year), clones each shallowly, reads its settings and rules through `gh api`, runs every check
of standard.toml (checks.py) and writes site/index.html and site/audit.json. With --issues it
opens or updates one issue per drifting repository, titled ISSUE_TITLE, and closes it once the
repository has no drift.

Exit 0: no repository drifts. Exit 1: at least one drifts. Exit 2: the standard, the
repository list or a clone cannot be read.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import subprocess  # noqa: S404 - runs gh and git, the audit's only tools
import sys
import tempfile
import tomllib
from collections.abc import Sequence
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import checks  # noqa: E402
import report  # noqa: E402

GATES = pathlib.Path(__file__).resolve().parent.parent.parent
ISSUE_TITLE = "Drift from the paxel/gates standard"


def gh(*args: str) -> Any:
    p = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607
    if p.returncode != 0:
        return {"_error": (p.stderr or p.stdout).strip()[:300]}
    out = p.stdout.strip()
    try:
        return json.loads(out) if out else None
    except json.JSONDecodeError:
        return out


def status(path: str) -> str:
    p = subprocess.run(["gh", "api", "-i", path], capture_output=True, text=True, check=False)  # noqa: S603, S607
    first = (p.stdout or p.stderr).splitlines()[:1]
    return first[0] if first else "?"


def active(owner: str, year: int) -> list[dict[str, Any]]:
    repos = gh(
        "repo",
        "list",
        owner,
        "--limit",
        "500",
        "--json",
        "name,isFork,isArchived,pushedAt,defaultBranchRef",
    )
    if not isinstance(repos, list):
        raise OSError(f"cannot list the repositories of {owner}: {repos}")
    return [
        r
        for r in repos
        if not r["isFork"] and not r["isArchived"] and str(r.get("pushedAt", "")) >= f"{year}-01-01"
    ]


def settings(owner: str, name: str) -> dict[str, Any]:
    repo = gh("api", f"repos/{owner}/{name}")
    saa = (repo or {}).get("security_and_analysis") or {} if isinstance(repo, dict) else {}
    pvr = gh("api", f"repos/{owner}/{name}/private-vulnerability-reporting")
    fixes = gh("api", f"repos/{owner}/{name}/automated-security-fixes")
    alerts = status(f"repos/{owner}/{name}/vulnerability-alerts")
    return {
        "secret_scanning": (saa.get("secret_scanning") or {}).get("status"),
        "push_protection": (saa.get("secret_scanning_push_protection") or {}).get("status"),
        "private_vulnerability_reporting": pvr.get("enabled") if isinstance(pvr, dict) else None,
        "automated_security_fixes": fixes.get("enabled") if isinstance(fixes, dict) else None,
        "vulnerability_alerts": "on" if "204" in alerts else "off",
    }


def last_commit(root: pathlib.Path) -> str:
    p = subprocess.run(
        ["git", "-C", str(root), "log", "-1", "--format=%cs"], capture_output=True, text=True, check=False
    )  # noqa: S603, S607
    return p.stdout.strip()


def latest_release(owner: str) -> tuple[str | None, str | None]:
    rel = gh("api", f"repos/{owner}/gates/releases/latest")
    if not isinstance(rel, dict) or "tag_name" not in rel:
        return None, None
    tag = str(rel["tag_name"])
    commit = gh("api", f"repos/{owner}/gates/commits/{tag}")
    return (str(commit["sha"]) if isinstance(commit, dict) and "sha" in commit else None), tag


def audit_repo(
    owner: str, meta: dict[str, Any], work: pathlib.Path, standard: dict[str, Any], ctx: checks.Context
) -> dict[str, Any]:
    name = str(meta["name"])
    branch = str((meta.get("defaultBranchRef") or {}).get("name") or "main")
    root = work / name
    clone = subprocess.run(  # noqa: S603, S607
        ["gh", "repo", "clone", f"{owner}/{name}", str(root), "--", "--depth", "1", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    if clone.returncode != 0:
        raise OSError(f"cannot clone {owner}/{name}: {clone.stderr.strip()[:200]}")
    rules = gh("api", f"repos/{owner}/{name}/rules/branches/{branch}")
    repo = checks.Repo(
        name=name,
        root=root,
        default_branch=branch,
        settings=settings(owner, name),
        rules=rules if isinstance(rules, list) else [],
    )
    repo.stacks = checks.find_stacks(root, standard)
    repo.contents = checks.find_contents(root, standard, repo.stacks)
    results = checks.run(repo, standard, ctx)
    return {
        "repo": name,
        "default_branch": branch,
        "last_commit": last_commit(root),
        "stacks": repo.stacks,
        "contents": repo.contents,
        "results": [r.__dict__ for r in results],
    }


def issue_body(entry: dict[str, Any], standard: dict[str, Any]) -> str:
    labels = {str(c["id"]): str(c["label"]) for c in standard.get("checks") or []}
    lines = [
        f"The weekly audit of [paxel/gates](https://github.com/paxel/gates) found {entry['repo']} "
        "drifting from the standard ([standard.toml](https://github.com/paxel/gates/blob/summer/standard.toml)).",
        "",
        "| Check | What is wrong |",
        "|-------|---------------|",
    ]
    for r in entry["results"]:
        if r["state"] == "drift":
            lines.append(f"| {labels.get(r['check'], r['check'])} | {r['detail'] or 'missing'} |")
    lines += ["", "This issue is updated by every audit run and closed once nothing drifts."]
    return "\n".join(lines) + "\n"


def sync_issue(owner: str, entry: dict[str, Any], standard: dict[str, Any]) -> None:
    repo = f"{owner}/{entry['repo']}"
    found = gh(
        "issue",
        "list",
        "--repo",
        repo,
        "--state",
        "open",
        "--search",
        f'"{ISSUE_TITLE}" in:title',
        "--json",
        "number,title",
    )
    numbers = [i["number"] for i in found if i["title"] == ISSUE_TITLE] if isinstance(found, list) else []
    drift = any(r["state"] == "drift" for r in entry["results"])
    if drift:
        body = issue_body(entry, standard)
        if numbers:
            gh("issue", "edit", str(numbers[0]), "--repo", repo, "--body", body)
        else:
            gh("issue", "create", "--repo", repo, "--title", ISSUE_TITLE, "--body", body)
    else:
        for n in numbers:
            gh("issue", "close", str(n), "--repo", repo, "--comment", "The audit found no drift.")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="audit.py")
    parser.add_argument("--out", required=True)
    parser.add_argument("--issues", action="store_true", help="open, update and close the drift issues")
    parser.add_argument("--only", action="append", default=[], help="audit only this repository")
    args = parser.parse_args(argv)
    try:
        standard = tomllib.loads((GATES / "standard.toml").read_text(encoding="utf-8"))
        owner = str(standard["active"]["owner"])
        now = datetime.datetime.now(datetime.UTC)
        repos = active(owner, now.year)
        sha, tag = latest_release(owner)
        ctx = checks.Context(gates=GATES, latest_sha=sha, latest_tag=tag)
        entries = []
        with tempfile.TemporaryDirectory() as tmp:
            for meta in sorted(repos, key=lambda r: str(r["name"]).lower()):
                if args.only and meta["name"] not in args.only:
                    continue
                entry = audit_repo(owner, meta, pathlib.Path(tmp), standard, ctx)
                if entry["last_commit"] < f"{now.year}-01-01":
                    continue
                entries.append(entry)
    except (OSError, ValueError, KeyError) as error:
        print(f"audit: {error}", file=sys.stderr)
        return 2
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = {"when": now.isoformat(timespec="minutes"), "gates": tag, "repos": entries}
    (out / "audit.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    (out / "index.html").write_text(report.render(data, standard), encoding="utf-8")
    drifting = [e["repo"] for e in entries if any(r["state"] == "drift" for r in e["results"])]
    if args.issues:
        for entry in entries:
            sync_issue(owner, entry, standard)
    for entry in entries:
        n = sum(1 for r in entry["results"] if r["state"] == "drift")
        print(f"{entry['repo']}: {n} drifting checks")
    print(f"{len(entries)} active repositories, {len(drifting)} drifting")
    return 1 if drifting else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
