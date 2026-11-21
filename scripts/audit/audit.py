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
import urllib.request
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


def failure(answer: Any) -> str | None:
    """Why an answer of gh() is no answer, or None if it is one."""
    if isinstance(answer, dict):
        return str(answer["_error"]) if "_error" in answer else None
    return f"unexpected answer: {str(answer)[:80]}"


def settings(owner: str, name: str) -> dict[str, Any]:
    """The repository's security settings. A setting GitHub did not answer for is listed
    under "unreadable" with the reason, so a failed read is never reported as "off"."""
    found: dict[str, Any] = {}
    unreadable: dict[str, str] = {}

    repo = gh("api", f"repos/{owner}/{name}")
    error = failure(repo)
    raw = repo.get("security_and_analysis") if error is None else None
    if error is None and not isinstance(raw, dict):
        # GitHub leaves the field out for a token without admin access to the repository.
        error = "no security_and_analysis in the answer (the token needs admin access)"
    saa: dict[str, Any] = raw if isinstance(raw, dict) else {}
    for key, field in (
        ("secret_scanning", "secret_scanning"),
        ("push_protection", "secret_scanning_push_protection"),
    ):
        if error is None:
            found[key] = (saa.get(field) or {}).get("status")
        else:
            found[key] = None
            unreadable[key] = error

    pvr = gh("api", f"repos/{owner}/{name}/private-vulnerability-reporting")
    error = failure(pvr)
    found["private_vulnerability_reporting"] = pvr.get("enabled") if error is None else None
    if error is not None:
        unreadable["private_vulnerability_reporting"] = error

    # GitHub answers 404 for automated security fixes and for the alerts when they are off.
    fixes = gh("api", f"repos/{owner}/{name}/automated-security-fixes")
    error = failure(fixes)
    found["automated_security_fixes"] = fixes.get("enabled") if error is None else None
    if error is not None and "404" not in error:
        unreadable["automated_security_fixes"] = error

    alerts = status(f"repos/{owner}/{name}/vulnerability-alerts")
    found["vulnerability_alerts"] = "on" if " 204" in alerts else "off"
    if " 204" not in alerts and " 404" not in alerts:
        unreadable["vulnerability_alerts"] = alerts

    # Names only; GitHub never returns a secret's value.
    listed = gh("api", f"repos/{owner}/{name}/actions/secrets?per_page=100")
    error = failure(listed)
    names = listed.get("secrets") if error is None else None
    if error is None and not isinstance(names, list):
        error = "no secrets in the answer"
    found["secrets"] = [str(s.get("name")) for s in names] if isinstance(names, list) else None
    if error is not None:
        unreadable["secrets"] = error

    if unreadable:
        found["unreadable"] = unreadable
    return found


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


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https URLs
        return str(response.read().decode("utf-8"))


def latest_toolchains() -> dict[str, str]:
    """The latest stable Rust, Go, Flutter and Node LTS; a source that fails is left out."""
    found: dict[str, str] = {}
    try:
        channel = tomllib.loads(fetch("https://static.rust-lang.org/dist/channel-rust-stable.toml"))
        found["rust"] = str(channel["pkg"]["rust"]["version"]).split(" ")[0]
    except (OSError, ValueError, KeyError):
        pass
    try:
        found["go"] = str(json.loads(fetch("https://go.dev/dl/?mode=json"))[0]["version"]).removeprefix("go")
    except (OSError, ValueError, KeyError, IndexError):
        pass
    try:
        releases = json.loads(
            fetch("https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json")
        )
        stable = releases["current_release"]["stable"]
        found["dart"] = next(str(r["version"]) for r in releases["releases"] if r["hash"] == stable)
    except (OSError, ValueError, KeyError, StopIteration):
        pass
    try:
        lts = [r for r in json.loads(fetch("https://nodejs.org/dist/index.json")) if r.get("lts")]
        found["ts"] = str(lts[0]["version"]).lstrip("v")
    except (OSError, ValueError, KeyError, IndexError):
        pass
    return found


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
        ctx = checks.Context(gates=GATES, latest_sha=sha, latest_tag=tag, toolchains=latest_toolchains())
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
    if not entries:
        # Early in January no repository has a commit of the new year yet; an audit of nothing
        # must not pass.
        print("audit: no active repository found; nothing was audited", file=sys.stderr)
        return 1
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
