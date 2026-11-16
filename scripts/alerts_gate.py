"""Decides whether open alerts and SonarQube Cloud findings stop a run.

The code-scanning and secret-scanning alerts come from GitHub's API, one JSON object per line:

    gh api --paginate "repos/$R/code-scanning/alerts?state=open&ref=$REF&per_page=100" --jq '.[]' > code.jsonl
    gh api --paginate "repos/$R/secret-scanning/alerts?state=open&per_page=100" \\
        --jq '.[] | del(.secret)' > secrets.jsonl
    python3 alerts_gate.py --code code.jsonl --secrets secrets.jsonl --ignores code-scanning-ignores.toml

A repository with a SonarQube Cloud project adds --sonar sonar.jsonl: its open issues and its
security hotspots to review, as api/issues/search and api/hotspots/search return them, one
object per line. SonarQube Cloud's own quality gate looks at new code only; this list is all
of them.

Every open code-scanning alert, of any tool and severity, blocks unless an [[IgnoredAlerts]]
entry names its tool, its rule and, when the alert is in a file, that file as path, with a
reason and an ignoreUntil date that has not passed. An entry covers its rule in that one file;
an entry without a path covers only an alert that has no file (Scorecard's repository-level
ones), and one that leaves out the path of an alert in a file blocks.
Every open secret-scanning alert blocks unless an [[IgnoredSecrets]] entry names its secret
type the same way. An entry without a reason or a date, or with a passed date, blocks too;
that is the review. An entry without an open alert is listed so it can go.
Every SonarQube Cloud issue, of any type and severity, and every hotspot to review blocks
unless an [[IgnoredAlerts]] entry with tool "SonarQube Cloud" names its rule (as SonarQube
Cloud writes it, e.g. pythonsecurity:S8707) and its file. Nothing is marked in SonarQube
Cloud's web UI.

The secret list is required beside the code-scanning one: GITHUB_TOKEN cannot read it, and a
gate that could not read it must not pass. CI's sonar job passes --sonar alone, right after
the scan; then only the SonarQube Cloud findings and their entries are judged.

Exit 0: nothing blocks. Exit 1: something blocks. Exit 2: an input cannot be read.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import tomllib
from collections.abc import Callable, Sequence
from typing import Any

# Tool, rule and file; the file is empty for a finding that has none.
Key = tuple[str, str, str]
# What GitHub puts where the file would be, for an alert about the repository as a whole.
NO_FILE = "no file associated with this alert"
SONAR = "SonarQube Cloud"
Finding = dict[str, Any]
# One list of findings, how to key one, and how to print one.
Source = tuple[list[Finding], Callable[[Finding], Key], Callable[[Finding], str]]


def read_jsonl(path: str) -> list[dict[str, Any]]:
    """The alerts, each once even when several branches report it."""
    alerts: dict[str, dict[str, Any]] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alert = json.loads(line)
                alerts[str(alert.get("html_url") or alert.get("number") or alert.get("key"))] = alert
    return list(alerts.values())


def problems(entry: dict[str, Any], today: datetime.date) -> list[str]:
    found = []
    if not str(entry.get("reason") or "").strip():
        found.append("no reason")
    until = entry.get("ignoreUntil")
    if not isinstance(until, datetime.date):
        found.append("no ignoreUntil date")
    elif until < today:
        found.append(f"ignoreUntil {until} has passed")
    return found


def code_path(alert: dict[str, Any]) -> str:
    location = (alert.get("most_recent_instance") or {}).get("location") or {}
    path = str(location.get("path") or "")
    return "" if path == NO_FILE else path


def code_key(alert: dict[str, Any]) -> Key:
    tool = str((alert.get("tool") or {}).get("name"))
    return (tool, str((alert.get("rule") or {}).get("id")), code_path(alert))


def leak_key(alert: dict[str, Any]) -> Key:
    return ("secret-scanning", str(alert.get("secret_type")), "")


def entry_key(section: str, entry: dict[str, Any]) -> Key:
    if section == "IgnoredSecrets":
        return ("secret-scanning", str(entry.get("secret_type")), "")
    return (str(entry.get("tool")), str(entry.get("rule")), str(entry.get("path") or ""))


def name(key: Key) -> str:
    return " ".join(part for part in key if part)


def describe_code(alert: dict[str, Any]) -> str:
    rule = alert.get("rule") or {}
    severity = rule.get("security_severity_level") or rule.get("severity") or "?"
    tool, rule_id, path = code_key(alert)
    return f"{tool} {rule_id} ({severity}) {path or 'no file'} {alert.get('html_url', '')}"


def describe_leak(alert: dict[str, Any]) -> str:
    kind = alert.get("secret_type_display_name") or alert.get("secret_type")
    return f"secret {kind} {alert.get('html_url', '')}"


def sonar_path(finding: dict[str, Any]) -> str:
    """The file of an issue or hotspot; its component is "<project key>:<path>"."""
    project = str(finding.get("project") or "")
    component = str(finding.get("component") or "")
    return component.removeprefix(project + ":") if project and component != project else ""


def sonar_key(finding: dict[str, Any]) -> Key:
    return (SONAR, str(finding.get("rule") or finding.get("ruleKey")), sonar_path(finding))


def describe_sonar(finding: dict[str, Any]) -> str:
    # An issue has a rule and a severity, a hotspot a ruleKey and a probability.
    kind = "issue" if finding.get("rule") else "hotspot"
    severity = str(finding.get("severity") or finding.get("vulnerabilityProbability") or "?").lower()
    where = f"{sonar_path(finding) or 'no file'}:{finding.get('line', '?')}"
    rule = sonar_key(finding)[1]
    return f"{SONAR} {rule} ({kind}, {severity}) {where} {finding.get('message', '')}"


def source_of(key: Key) -> str:
    return {SONAR: "sonar", "secret-scanning": "leaks"}.get(key[0], "code")


def gate(
    code: list[Finding] | None,
    leaks: list[Finding] | None,
    ignores: dict[str, Any],
    today: datetime.date,
    sonar: list[Finding] | None = None,
) -> tuple[list[str], int]:
    """The lines to print and how many of them block; a list that is None was not read."""
    lines: list[str] = []
    blocking = 0
    entries: dict[Key, dict[str, Any]] = {}
    for section in ("IgnoredAlerts", "IgnoredSecrets"):
        for entry in ignores.get(section) or []:
            key = entry_key(section, entry)
            bad = problems(entry, today)
            if bad:
                lines.append(f"BAD ENTRY: {section} {name(key)}: {', '.join(bad)}")
                blocking += 1
            else:
                entries[key] = entry
    seen: set[Key] = set()
    pathless: set[Key] = set()
    read = {"code": code is not None, "leaks": leaks is not None, "sonar": sonar is not None}
    lists: list[Source] = [
        (code or [], code_key, describe_code),
        (leaks or [], leak_key, describe_leak),
        (sonar or [], sonar_key, describe_sonar),
    ]
    for alerts, key_of, describe in lists:
        for alert in alerts:
            key = key_of(alert)
            seen.add(key)
            entry = entries.get(key)
            if entry:
                lines.append(f"accepted until {entry['ignoreUntil']}: {describe(alert)}")
            else:
                lines.append(f"OPEN: {describe(alert)}")
                blocking += 1
                if key[2] and (key[0], key[1], "") in entries:
                    pathless.add((key[0], key[1], ""))
    for key in sorted(pathless):
        lines.append(f"BAD ENTRY: IgnoredAlerts {name(key)}: no path, but the finding is in a file")
        blocking += 1
    for key in entries:
        # Nothing is known about the entries of a list that was not read.
        if key not in seen and key not in pathless and read[source_of(key)]:
            lines.append(f"no open alert, the entry can go: {name(key)}")
    counted = []
    if code is not None and leaks is not None:
        counted.append(f"{len(code)} code-scanning and {len(leaks)} secret-scanning alerts")
    if sonar is not None:
        counted.append(f"{len(sonar)} SonarQube Cloud findings")
    lines.append(f"{' and '.join(counted)} open, {blocking} blocking")
    return lines, blocking


def main(argv: Sequence[str], today: datetime.date | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alerts_gate.py")
    parser.add_argument("--code")
    parser.add_argument("--secrets", dest="leaks")
    parser.add_argument("--ignores", required=True)
    parser.add_argument("--sonar", help="SonarQube Cloud's open issues and hotspots to review")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    alerts = bool(args.code) and bool(args.leaks)
    if (args.code or args.leaks or not args.sonar) and not alerts:
        print("pass --code and --secrets, --sonar, or all three", file=sys.stderr)
        return 2
    try:
        code = read_jsonl(args.code) if alerts else None
        leaks = read_jsonl(args.leaks) if alerts else None
        sonar = read_jsonl(args.sonar) if args.sonar else None
        with open(args.ignores, "rb") as f:
            ignores = tomllib.load(f)
    except (OSError, ValueError) as error:
        print(f"cannot read the alerts or the ignores: {error}", file=sys.stderr)
        return 2
    lines, blocking = gate(code, leaks, ignores, today or datetime.date.today(), sonar)
    for line in lines:
        print(line)
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
