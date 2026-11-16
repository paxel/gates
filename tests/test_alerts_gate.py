import datetime
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from typing import Any

from alerts_gate import NO_FILE, main

TODAY = datetime.date(2026, 11, 15)


def alert(tool: str, rule: str, url: str, severity: str = "high", path: str = NO_FILE) -> dict[str, Any]:
    """An alert as GitHub reports it; one about the repository as a whole has NO_FILE as path."""
    return {
        "html_url": url,
        "tool": {"name": tool},
        "rule": {"id": rule, "security_severity_level": severity},
        "most_recent_instance": {"location": {"path": path}},
    }


def issue(rule: str, path: str, key: str = "k1", severity: str = "MAJOR") -> dict[str, Any]:
    """An issue as SonarQube Cloud's api/issues/search returns it."""
    component = f"paxel_x:{path}" if path else "paxel_x"
    found = {"key": key, "rule": rule, "project": "paxel_x", "component": component, "severity": severity}
    return {**found, "type": "VULNERABILITY", "line": 7, "message": "Path traversal"}


def hotspot(rule: str, path: str, key: str = "h1") -> dict[str, Any]:
    """A hotspot as SonarQube Cloud's api/hotspots/search returns it."""
    found = {"key": key, "ruleKey": rule, "project": "paxel_x", "component": f"paxel_x:{path}"}
    return {**found, "vulnerabilityProbability": "MEDIUM", "line": 3, "message": "Review this"}


def accept(tool: str, rule: str, path: str = "") -> str:
    where = f'path = "{path}"\n' if path else ""
    head = f'[[IgnoredAlerts]]\ntool = "{tool}"\nrule = "{rule}"\n'
    return f'{head}{where}ignoreUntil = 2027-05-14\nreason = "r"\n'


def leak(kind: str, url: str) -> dict[str, Any]:
    return {"html_url": url, "secret_type": kind, "secret_type_display_name": kind.title()}


ACCEPT = (
    '[[IgnoredAlerts]]\ntool = "Scorecard"\nrule = "CodeReviewID"\n'
    'ignoreUntil = 2027-05-14\nreason = "single maintainer"\n'
)


class AlertsGateTest(unittest.TestCase):
    def run_gate(
        self,
        code: list[dict[str, Any]],
        leaks: list[dict[str, Any]] | None = None,
        ignores: str = "",
        sonar: list[dict[str, Any]] | None = None,
    ) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "code.jsonl").write_text("".join(json.dumps(a) + "\n" for a in code))
            (t / "secrets.jsonl").write_text("".join(json.dumps(a) + "\n" for a in (leaks or [])))
            (t / "ignores.toml").write_text(ignores)
            extra = []
            if sonar is not None:
                (t / "sonar.jsonl").write_text("".join(json.dumps(a) + "\n" for a in sonar))
                extra = ["--sonar", str(t / "sonar.jsonl")]
            out = StringIO()
            with redirect_stdout(out):
                result = main(
                    [
                        "--code",
                        str(t / "code.jsonl"),
                        "--secrets",
                        str(t / "secrets.jsonl"),
                        "--ignores",
                        str(t / "ignores.toml"),
                        *extra,
                    ],
                    today=TODAY,
                )
            return result, out.getvalue()

    def test_nothing_open_passes(self) -> None:
        code, out = self.run_gate([])
        self.assertEqual(code, 0)
        self.assertIn("0 code-scanning and 0 secret-scanning alerts open, 0 blocking", out)

    def test_an_alert_of_any_tool_and_severity_blocks(self) -> None:
        code, out = self.run_gate([alert("Scorecard", "FuzzingID", "u1", "low")])
        self.assertEqual(code, 1)
        self.assertIn("OPEN: Scorecard FuzzingID (low) no file", out)

    def test_an_accepted_alert_passes(self) -> None:
        code, out = self.run_gate([alert("Scorecard", "CodeReviewID", "u1")], ignores=ACCEPT)
        self.assertEqual(code, 0)
        self.assertIn("accepted until 2027-05-14", out)

    def test_an_entry_only_accepts_its_own_tool(self) -> None:
        self.assertEqual(self.run_gate([alert("CodeQL", "CodeReviewID", "u1")], ignores=ACCEPT)[0], 1)

    def test_an_alert_in_a_file_is_accepted_for_that_file_only(self) -> None:
        found = [alert("CodeQL", "py/x", "u1", path="scripts/a.py")]
        code, out = self.run_gate(found, ignores=accept("CodeQL", "py/x", "scripts/a.py"))
        self.assertEqual(code, 0)
        self.assertIn("accepted until 2027-05-14: CodeQL py/x (high) scripts/a.py", out)
        code, out = self.run_gate(found, ignores=accept("CodeQL", "py/x", "scripts/b.py"))
        self.assertEqual(code, 1)
        self.assertIn("OPEN: CodeQL py/x (high) scripts/a.py", out)
        self.assertIn("the entry can go: CodeQL py/x scripts/b.py", out)

    def test_an_entry_without_the_path_of_its_finding_blocks(self) -> None:
        found = [
            alert("CodeQL", "py/x", "u1", path="scripts/a.py"),
            alert("CodeQL", "py/x", "u2", path="b.py"),
        ]
        code, out = self.run_gate(found, ignores=accept("CodeQL", "py/x"))
        self.assertEqual(code, 1)
        self.assertIn("BAD ENTRY: IgnoredAlerts CodeQL py/x: no path, but the finding is in a file", out)
        self.assertIn("2 code-scanning and 0 secret-scanning alerts open, 3 blocking", out)
        self.assertNotIn("the entry can go", out)

    def test_an_entry_with_a_path_does_not_accept_a_finding_without_a_file(self) -> None:
        found = [alert("Scorecard", "CodeReviewID", "u1")]
        self.assertEqual(self.run_gate(found, ignores=accept("Scorecard", "CodeReviewID", "a.py"))[0], 1)

    def test_a_sonar_issue_of_any_severity_blocks(self) -> None:
        code, out = self.run_gate([], sonar=[issue("python:S1", "scripts/a.py", severity="INFO")])
        self.assertEqual(code, 1)
        self.assertIn("OPEN: SonarQube Cloud python:S1 (issue, info) scripts/a.py:7 Path traversal", out)
        self.assertIn("0 secret-scanning alerts and 1 SonarQube Cloud findings open, 1 blocking", out)

    def test_a_hotspot_to_review_blocks(self) -> None:
        code, out = self.run_gate([], sonar=[hotspot("python:S4", "scripts/a.py")])
        self.assertEqual(code, 1)
        self.assertIn("OPEN: SonarQube Cloud python:S4 (hotspot, medium) scripts/a.py:3", out)

    def test_a_sonar_finding_is_accepted_for_its_rule_and_file(self) -> None:
        found = [issue("python:S1", "scripts/a.py"), issue("python:S1", "scripts/a.py", "k2")]
        ignores = accept("SonarQube Cloud", "python:S1", "scripts/a.py")
        self.assertEqual(self.run_gate([], ignores=ignores, sonar=found)[0], 0)
        other = [issue("python:S1", "scripts/b.py"), hotspot("python:S4", "scripts/a.py")]
        code, out = self.run_gate([], ignores=ignores, sonar=other)
        self.assertEqual(code, 1)
        self.assertIn("2 blocking", out)

    def test_a_sonar_finding_on_the_project_has_no_file(self) -> None:
        ignores = accept("SonarQube Cloud", "python:S1")
        self.assertEqual(self.run_gate([], ignores=ignores, sonar=[issue("python:S1", "")])[0], 0)

    def test_sonar_entries_are_left_alone_without_the_list(self) -> None:
        ignores = accept("SonarQube Cloud", "python:S1", "scripts/a.py")
        self.assertNotIn("can go", self.run_gate([], ignores=ignores)[1])
        self.assertIn(
            "can go: SonarQube Cloud python:S1 scripts/a.py", self.run_gate([], ignores=ignores, sonar=[])[1]
        )

    def test_an_unreadable_sonar_list_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(StringIO()):
            t = pathlib.Path(tmp)
            for f in ("code.jsonl", "leaks.jsonl", "ignores.toml"):
                (t / f).write_text("")
            base = ["--code", str(t / "code.jsonl"), "--secrets", str(t / "leaks.jsonl")]
            base += ["--ignores", str(t / "ignores.toml")]
            self.assertEqual(main([*base, "--sonar", str(t / "missing")]), 2)

    def test_an_open_secret_blocks(self) -> None:
        code, out = self.run_gate([], [leak("github_personal_access_token", "s1")])
        self.assertEqual(code, 1)
        self.assertIn("OPEN: secret Github_Personal_Access_Token s1", out)

    def test_an_accepted_secret_passes(self) -> None:
        ignores = (
            '[[IgnoredSecrets]]\nsecret_type = "test_token"\n'
            'ignoreUntil = 2027-01-01\nreason = "fixture token, revoked"\n'
        )
        self.assertEqual(self.run_gate([], [leak("test_token", "s1")], ignores)[0], 0)

    def test_a_passed_date_blocks(self) -> None:
        code, out = self.run_gate(
            [alert("Scorecard", "CodeReviewID", "u1")], ignores=ACCEPT.replace("2027-05-14", "2026-11-14")
        )
        self.assertEqual(code, 1)
        self.assertIn("ignoreUntil 2026-11-14 has passed", out)

    def test_an_entry_without_reason_or_date_blocks(self) -> None:
        code, out = self.run_gate([], ignores='[[IgnoredAlerts]]\ntool = "Scorecard"\nrule = "X"\n')
        self.assertEqual(code, 1)
        self.assertIn("no reason, no ignoreUntil date", out)

    def test_an_entry_without_an_alert_is_listed_only(self) -> None:
        code, out = self.run_gate([], ignores=ACCEPT)
        self.assertEqual(code, 0)
        self.assertIn("the entry can go: Scorecard CodeReviewID", out)

    def test_the_same_alert_twice_counts_once(self) -> None:
        a = alert("CodeQL", "rust/x", "u1")
        self.assertIn("1 code-scanning", self.run_gate([a, a])[1])

    def test_a_missing_secret_list_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(StringIO()):
            missing = str(pathlib.Path(tmp) / "missing")
            self.assertEqual(main(["--code", missing, "--secrets", missing, "--ignores", missing]), 2)
            self.assertEqual(main(["--code", missing, "--ignores", missing]), 2)


if __name__ == "__main__":
    unittest.main()
