"""Decides whether open code-scanning and secret-scanning alerts stop a run.

Both lists come from GitHub's API, one JSON object per line:

    gh api --paginate "repos/$R/code-scanning/alerts?state=open&ref=$REF&per_page=100" --jq '.[]' > code.jsonl
    gh api --paginate "repos/$R/secret-scanning/alerts?state=open&per_page=100" \\
        --jq '.[] | del(.secret)' > secrets.jsonl
    python3 alerts_gate.py --code code.jsonl --secrets secrets.jsonl --ignores code-scanning-ignores.toml

Every open code-scanning alert, of any tool and severity, blocks unless an [[IgnoredAlerts]]
entry names its tool, its rule and, when the alert is in a file, that file as path, with a
reason and an ignoreUntil date that has not passed. An entry covers its rule in that one file;
an entry without a path covers only an alert that has no file (Scorecard's repository-level
ones), and one that leaves out the path of an alert in a file blocks.
Every open secret-scanning alert blocks unless an [[IgnoredSecrets]] entry names its secret
type the same way. An entry without a reason or a date, or with a passed date, blocks too;
that is the review. An entry without an open alert is listed so it can go.

The secret list is required: GITHUB_TOKEN cannot read it, and a gate that could not read it
must not pass.

Exit 0: nothing blocks. Exit 1: something blocks. Exit 2: an input cannot be read.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import tomllib
from collections.abc import Sequence
from typing import Any

# Tool, rule and file; the file is empty for a finding that has none.
Key = tuple[str, str, str]
# What GitHub puts where the file would be, for an alert about the repository as a whole.
NO_FILE = "no file associated with this alert"


def read_jsonl(path: str) -> list[dict[str, Any]]:
    """The alerts, each once even when several branches report it."""
    alerts: dict[str, dict[str, Any]] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                alert = json.loads(line)
                alerts[str(alert.get("html_url") or alert.get("number"))] = alert
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


def gate(
    code: list[dict[str, Any]],
    leaks: list[dict[str, Any]],
    ignores: dict[str, Any],
    today: datetime.date,
) -> tuple[list[str], int]:
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
    for alerts, key_of, describe in ((code, code_key, describe_code), (leaks, leak_key, describe_leak)):
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
        if key not in seen and key not in pathless:
            lines.append(f"no open alert, the entry can go: {name(key)}")
    lines.append(
        f"{len(code)} code-scanning and {len(leaks)} secret-scanning alerts open, {blocking} blocking"
    )
    return lines, blocking


def main(argv: Sequence[str], today: datetime.date | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alerts_gate.py")
    parser.add_argument("--code", required=True)
    parser.add_argument("--secrets", dest="leaks", required=True)
    parser.add_argument("--ignores", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        code = read_jsonl(args.code)
        leaks = read_jsonl(args.leaks)
        with open(args.ignores, "rb") as f:
            ignores = tomllib.load(f)
    except (OSError, ValueError) as error:
        print(f"cannot read the alerts or the ignores: {error}", file=sys.stderr)
        return 2
    lines, blocking = gate(code, leaks, ignores, today or datetime.date.today())
    for line in lines:
        print(line)
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
