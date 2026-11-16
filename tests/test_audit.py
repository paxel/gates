import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "audit"))

import audit  # noqa: E402
import checks  # noqa: E402
import report  # noqa: E402

STANDARD: dict[str, Any] = {
    "active": {"owner": "paxel"},
    "checks": [
        {"id": "a", "label": "Check <A>", "group": "one", "applies": "all"},
        {"id": "b", "label": "Check B", "group": "two", "applies": "all"},
    ],
}


def done(code: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr=err)


def entry(name: str, state: str) -> dict[str, Any]:
    return {
        "repo": name,
        "default_branch": "summer",
        "last_commit": "2999-01-02",
        "stacks": ["rust"],
        "contents": [],
        "results": [{"check": "a", "state": state, "detail": "no <floor>"}],
    }


class ReportTest(unittest.TestCase):
    def test_the_page_shows_every_state_and_escapes(self) -> None:
        repos = [entry("x", "drift"), entry("y", "present")]
        data = {"when": "2026-11-16T05:00", "gates": None, "repos": repos}
        page = report.render(data, STANDARD)
        self.assertIn("2 active repositories, 1 drifting", page)
        self.assertIn('<td class="c drift" title="no &lt;floor&gt;">✗</td>', page)
        self.assertIn('<td class="c present"', page)
        # Check b has no result for either repository.
        self.assertEqual(page.count('<td class="c na"'), 2)
        self.assertIn("Check &lt;A&gt;", page)
        self.assertIn("against gates summer", page)


class GhTest(unittest.TestCase):
    def test_gh_reads_json_text_nothing_and_errors(self) -> None:
        cases: list[tuple[subprocess.CompletedProcess[str], Any]] = [
            (done(out='{"a": 1}\n'), {"a": 1}),
            (done(out="plain"), "plain"),
            (done(out=""), None),
            (done(1, err="HTTP 404"), {"_error": "HTTP 404"}),
        ]
        for result, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(subprocess, "run", return_value=result):
                self.assertEqual(audit.gh("api", "x"), expected)

    def test_status_is_the_first_line(self) -> None:
        with mock.patch.object(subprocess, "run", return_value=done(out="HTTP/2.0 204 No Content\nx: y\n")):
            self.assertEqual(audit.status("p"), "HTTP/2.0 204 No Content")
        with mock.patch.object(subprocess, "run", return_value=done(1)):
            self.assertEqual(audit.status("p"), "?")

    def test_last_commit_is_the_date(self) -> None:
        with mock.patch.object(subprocess, "run", return_value=done(out="2026-11-16\n")):
            self.assertEqual(audit.last_commit(ROOT), "2026-11-16")


class ListingTest(unittest.TestCase):
    def test_active_drops_forks_archives_and_old_repositories(self) -> None:
        repos = [
            {"name": "live", "isFork": False, "isArchived": False, "pushedAt": "2026-03-01T00:00:00Z"},
            {"name": "fork", "isFork": True, "isArchived": False, "pushedAt": "2026-03-01T00:00:00Z"},
            {"name": "gone", "isFork": False, "isArchived": True, "pushedAt": "2026-03-01T00:00:00Z"},
            {"name": "old", "isFork": False, "isArchived": False, "pushedAt": "2025-12-31T00:00:00Z"},
        ]
        with mock.patch.object(audit, "gh", return_value=repos):
            self.assertEqual([r["name"] for r in audit.active("paxel", 2026)], ["live"])

    def test_an_unreadable_list_is_an_error(self) -> None:
        with mock.patch.object(audit, "gh", return_value={"_error": "no"}), self.assertRaises(OSError):
            audit.active("paxel", 2026)

    def test_settings_come_from_the_api(self) -> None:
        answers: dict[str, Any] = {
            "repos/paxel/x": {
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "disabled"},
                }
            },
            "repos/paxel/x/private-vulnerability-reporting": {"enabled": True},
            "repos/paxel/x/automated-security-fixes": {"_error": "404"},
        }
        with (
            mock.patch.object(audit, "gh", side_effect=lambda _api, path: answers[path]),
            mock.patch.object(audit, "status", return_value="HTTP/2.0 204 No Content"),
        ):
            found = audit.settings("paxel", "x")
        self.assertEqual(
            found,
            {
                "secret_scanning": "enabled",
                "push_protection": "disabled",
                "private_vulnerability_reporting": True,
                "automated_security_fixes": None,
                "vulnerability_alerts": "on",
            },
        )

    def test_settings_of_an_unreadable_repository_are_empty(self) -> None:
        with (
            mock.patch.object(audit, "gh", return_value="not json"),
            mock.patch.object(audit, "status", return_value="HTTP/2.0 404 Not Found"),
        ):
            found = audit.settings("paxel", "x")
        self.assertIsNone(found["secret_scanning"])
        self.assertEqual(found["vulnerability_alerts"], "off")

    def test_latest_release_is_its_commit_and_tag(self) -> None:
        with mock.patch.object(audit, "gh", side_effect=[{"tag_name": "v1.0.0"}, {"sha": "abc"}]):
            self.assertEqual(audit.latest_release("paxel"), ("abc", "v1.0.0"))
        with mock.patch.object(audit, "gh", side_effect=[{"tag_name": "v1.0.0"}, {"_error": "x"}]):
            self.assertEqual(audit.latest_release("paxel"), (None, "v1.0.0"))
        with mock.patch.object(audit, "gh", return_value={"_error": "Not Found"}):
            self.assertEqual(audit.latest_release("paxel"), (None, None))


class ToolchainsTest(unittest.TestCase):
    def test_fetch_decodes_the_response(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"text"
        with mock.patch("urllib.request.urlopen", return_value=response):
            self.assertEqual(audit.fetch("https://example.invalid"), "text")

    def test_every_source_is_read(self) -> None:
        def answer(url: str) -> str:
            if "rust-lang" in url:
                return '[pkg.rust]\nversion = "1.99.1 (abc 2026-01-01)"\n'
            if "go.dev" in url:
                return json.dumps([{"version": "go1.30.2"}])
            if "flutter" in url:
                return json.dumps(
                    {"current_release": {"stable": "h1"}, "releases": [{"hash": "h1", "version": "4.1.0"}]}
                )
            return json.dumps([{"version": "v26.0.0", "lts": False}, {"version": "v24.5.0", "lts": "Iron"}])

        with mock.patch.object(audit, "fetch", side_effect=answer):
            self.assertEqual(
                audit.latest_toolchains(), {"rust": "1.99.1", "go": "1.30.2", "dart": "4.1.0", "ts": "24.5.0"}
            )

    def test_a_failing_source_is_left_out(self) -> None:
        with mock.patch.object(audit, "fetch", side_effect=OSError("offline")):
            self.assertEqual(audit.latest_toolchains(), {})


class AuditRepoTest(unittest.TestCase):
    META: dict[str, Any] = {"name": "x", "defaultBranchRef": {"name": "summer"}}
    CTX = checks.Context(gates=ROOT, latest_sha=None, latest_tag=None)

    def test_a_repository_is_cloned_and_checked(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(subprocess, "run", return_value=done()),
            mock.patch.object(audit, "gh", return_value=[{"type": "deletion"}]),
            mock.patch.object(audit, "settings", return_value={}),
            mock.patch.object(audit, "last_commit", return_value="2026-11-16"),
            mock.patch.object(checks, "find_stacks", return_value=["rust"]),
            mock.patch.object(checks, "find_contents", return_value=[]),
            mock.patch.object(checks, "run", return_value=[checks.Result("a", "drift", "why")]) as run,
        ):
            found = audit.audit_repo("paxel", self.META, pathlib.Path(tmp), STANDARD, self.CTX)
        self.assertEqual(run.call_args.args[0].rules, [{"type": "deletion"}])
        self.assertEqual(
            found,
            {
                "repo": "x",
                "default_branch": "summer",
                "last_commit": "2026-11-16",
                "stacks": ["rust"],
                "contents": [],
                "results": [{"check": "a", "state": "drift", "detail": "why"}],
            },
        )

    def test_a_failed_clone_is_an_error(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(subprocess, "run", return_value=done(1, err="denied")),
            self.assertRaises(OSError),
        ):
            audit.audit_repo("paxel", self.META, pathlib.Path(tmp), STANDARD, self.CTX)


class IssueTest(unittest.TestCase):
    def test_the_body_lists_only_the_drift(self) -> None:
        item = entry("x", "drift")
        item["results"].append({"check": "b", "state": "present", "detail": ""})
        body = audit.issue_body(item, STANDARD)
        self.assertIn("| Check <A> | no <floor> |", body)
        self.assertNotIn("Check B", body)

    def sync(self, found: Any, state: str) -> list[tuple[str, ...]]:
        with mock.patch.object(audit, "gh", side_effect=[found, None, None]) as gh:
            audit.sync_issue("paxel", entry("x", state), STANDARD)
        return [call.args[:2] for call in gh.call_args_list[1:]]

    def test_drift_opens_or_updates_one_issue(self) -> None:
        mine = {"number": 7, "title": audit.ISSUE_TITLE}
        other = {"number": 8, "title": "Another " + audit.ISSUE_TITLE}
        self.assertEqual(self.sync([other], "drift"), [("issue", "create")])
        self.assertEqual(self.sync([other, mine], "drift"), [("issue", "edit")])
        self.assertEqual(self.sync({"_error": "x"}, "drift"), [("issue", "create")])

    def test_no_drift_closes_the_issue(self) -> None:
        mine = {"number": 7, "title": audit.ISSUE_TITLE}
        self.assertEqual(self.sync([mine], "present"), [("issue", "close")])
        self.assertEqual(self.sync([], "present"), [])


class MainTest(unittest.TestCase):
    def run_main(
        self, entries: list[dict[str, Any]], *extra: str, repos: Any = None
    ) -> tuple[int, str, str, pathlib.Path, mock.MagicMock]:
        metas = [{"name": e["repo"]} for e in entries]
        by_name = {e["repo"]: e for e in entries}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out_dir = pathlib.Path(tmp.name) / "site"
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(audit, "active", side_effect=repos, return_value=metas),
            mock.patch.object(audit, "latest_release", return_value=("abc", "v1.0.0")),
            mock.patch.object(audit, "latest_toolchains", return_value={}),
            mock.patch.object(audit, "audit_repo", side_effect=lambda _o, meta, *_: by_name[meta["name"]]),
            mock.patch.object(audit, "sync_issue") as sync,
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = audit.main(["--out", str(out_dir), *extra])
        return code, out.getvalue(), err.getvalue(), out_dir, sync

    def test_drift_fails_and_is_written(self) -> None:
        code, out, _, site, sync = self.run_main([entry("x", "drift"), entry("y", "present")])
        self.assertEqual(code, 1)
        self.assertIn("x: 1 drifting checks", out)
        self.assertIn("2 active repositories, 1 drifting", out)
        data = json.loads((site / "audit.json").read_text())
        self.assertEqual([r["repo"] for r in data["repos"]], ["x", "y"])
        self.assertEqual(data["gates"], "v1.0.0")
        self.assertIn("Gates Audit", (site / "index.html").read_text())
        sync.assert_not_called()

    def test_no_drift_passes(self) -> None:
        self.assertEqual(self.run_main([entry("y", "present")])[0], 0)

    def test_issues_are_synced_on_request(self) -> None:
        sync = self.run_main([entry("x", "drift"), entry("y", "present")], "--issues")[4]
        self.assertEqual(sync.call_count, 2)

    def test_only_narrows_the_audit(self) -> None:
        out = self.run_main([entry("x", "drift"), entry("y", "present")], "--only", "y")[1]
        self.assertIn("1 active repositories, 0 drifting", out)

    def test_an_audit_of_nothing_fails(self) -> None:
        stale = entry("x", "present")
        stale["last_commit"] = "2000-01-01"
        code, _, err, _, _ = self.run_main([stale])
        self.assertEqual(code, 1)
        self.assertIn("nothing was audited", err)

    def test_an_unreadable_list_is_exit_2(self) -> None:
        code, _, err, _, _ = self.run_main([], repos=OSError("cannot list"))
        self.assertEqual(code, 2)
        self.assertIn("audit: cannot list", err)


if __name__ == "__main__":
    unittest.main()
