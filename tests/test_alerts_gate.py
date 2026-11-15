import datetime
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from typing import Any

from alerts_gate import main

TODAY = datetime.date(2026, 11, 15)


def alert(tool: str, rule: str, url: str, severity: str = "high") -> dict[str, Any]:
    return {
        "html_url": url,
        "tool": {"name": tool},
        "rule": {"id": rule, "security_severity_level": severity},
        "most_recent_instance": {"location": {"path": "src/x.rs"}},
    }


def secret(kind: str, url: str) -> dict[str, Any]:
    return {"html_url": url, "secret_type": kind, "secret_type_display_name": kind.title()}


ACCEPT = (
    '[[IgnoredAlerts]]\ntool = "Scorecard"\nrule = "CodeReviewID"\n'
    'ignoreUntil = 2027-05-14\nreason = "single maintainer"\n'
)


class AlertsGateTest(unittest.TestCase):
    def run_gate(
        self, code: list[dict[str, Any]], secrets: list[dict[str, Any]] | None = None, ignores: str = ""
    ) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "code.jsonl").write_text("".join(json.dumps(a) + "\n" for a in code))
            (t / "secrets.jsonl").write_text("".join(json.dumps(a) + "\n" for a in (secrets or [])))
            (t / "ignores.toml").write_text(ignores)
            out = StringIO()
            with redirect_stdout(out):
                result = main(
                    ["--code", str(t / "code.jsonl"), "--secrets", str(t / "secrets.jsonl"),
                     "--ignores", str(t / "ignores.toml")],
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
        self.assertIn("OPEN: Scorecard FuzzingID (low)", out)

    def test_an_accepted_alert_passes(self) -> None:
        code, out = self.run_gate([alert("Scorecard", "CodeReviewID", "u1")], ignores=ACCEPT)
        self.assertEqual(code, 0)
        self.assertIn("accepted until 2027-05-14", out)

    def test_an_entry_only_accepts_its_own_tool(self) -> None:
        self.assertEqual(self.run_gate([alert("CodeQL", "CodeReviewID", "u1")], ignores=ACCEPT)[0], 1)

    def test_an_open_secret_blocks(self) -> None:
        code, out = self.run_gate([], [secret("github_personal_access_token", "s1")])
        self.assertEqual(code, 1)
        self.assertIn("OPEN: secret Github_Personal_Access_Token s1", out)

    def test_an_accepted_secret_passes(self) -> None:
        ignores = (
            '[[IgnoredSecrets]]\nsecret_type = "test_token"\n'
            'ignoreUntil = 2027-01-01\nreason = "fixture token, revoked"\n'
        )
        self.assertEqual(self.run_gate([], [secret("test_token", "s1")], ignores)[0], 0)

    def test_a_passed_date_blocks(self) -> None:
        code, out = self.run_gate([alert("Scorecard", "CodeReviewID", "u1")], ignores=ACCEPT.replace("2027-05-14", "2026-11-14"))
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
