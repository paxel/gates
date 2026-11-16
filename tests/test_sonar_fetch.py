import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from typing import Any
from unittest import mock

import sonar_fetch
from sonar_fetch import main, project_key, search


class Cloud:
    """Answers like SonarQube Cloud, page by page, and remembers what was asked."""

    def __init__(self, issues: list[dict[str, Any]], hotspots: list[dict[str, Any]]) -> None:
        self.lists = {"api/issues/search": ("issues", issues), "api/hotspots/search": ("hotspots", hotspots)}
        self.asked: list[tuple[str, dict[str, str]]] = []

    def __call__(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        self.asked.append((path, params))
        name, everything = self.lists[path]
        size, page = int(params["ps"]), int(params["p"])
        return {"paging": {"total": len(everything)}, name: everything[(page - 1) * size : page * size]}


class SonarFetchTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        self.properties = self.dir / "sonar-project.properties"
        self.properties.write_text("# comment\nsonar.organization=paxel\nsonar.projectKey = paxel_x\n")
        self.out = self.dir / "sonar.jsonl"

    def run_main(self, get: sonar_fetch.Get, *extra: str) -> tuple[int, str]:
        err = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            code = main(["--properties", str(self.properties), "--out", str(self.out), *extra], get)
        return code, err.getvalue()

    def written(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.out.read_text().splitlines()]

    def test_the_project_key_is_read_from_the_properties(self) -> None:
        self.assertEqual(project_key("a=b\nsonar.projectKey=paxel_x\n"), "paxel_x")
        with self.assertRaises(ValueError):
            project_key("sonar.projectKey=\n")

    def test_issues_and_hotspots_of_a_branch_are_written(self) -> None:
        cloud = Cloud([{"key": "i1", "rule": "python:S1"}], [{"key": "h1", "ruleKey": "python:S4"}])
        self.assertEqual(self.run_main(cloud, "--branch", "summer")[0], 0)
        self.assertEqual([f["key"] for f in self.written()], ["i1", "h1"])
        self.assertEqual({f["project"] for f in self.written()}, {"paxel_x"})
        path, params = cloud.asked[0]
        self.assertEqual(path, "api/issues/search")
        self.assertEqual(
            (params["componentKeys"], params["resolved"], params["branch"]), ("paxel_x", "false", "summer")
        )
        self.assertEqual(cloud.asked[1][1]["status"], "TO_REVIEW")

    def test_a_pull_request_adds_its_own_findings_to_the_branch(self) -> None:
        cloud = Cloud([{"key": "i1"}], [])
        self.assertEqual(self.run_main(cloud, "--branch", "summer", "--pull-request", "12")[0], 0)
        self.assertEqual(len(self.written()), 2)
        self.assertEqual([p.get("pullRequest") for _, p in cloud.asked], [None, None, "12", "12"])

    def test_every_page_is_read(self) -> None:
        cloud = Cloud([{"key": str(n)} for n in range(sonar_fetch.PAGE + 3)], [])
        self.assertEqual(len(search(cloud, "api/issues/search", {}, "issues")), sonar_fetch.PAGE + 3)
        self.assertEqual([p["p"] for _, p in cloud.asked], ["1", "2"])

    def test_more_results_than_can_be_read_is_an_error(self) -> None:
        def get(_path: str, _params: dict[str, str]) -> dict[str, Any]:
            return {"paging": {"total": sonar_fetch.LIMIT + 1}, "issues": [{}]}

        code, err = self.run_main(get, "--branch", "summer")
        self.assertEqual(code, 2)
        self.assertIn("more than the 10000", err)

    def test_an_answer_without_a_list_is_exit_2(self) -> None:
        code, err = self.run_main(lambda _path, _params: {"errors": [{"msg": "no"}]}, "--branch", "summer")
        self.assertEqual(code, 2)
        self.assertIn("cannot read the findings", err)
        self.assertFalse(self.out.exists())

    def test_an_unreachable_cloud_is_exit_2(self) -> None:
        def get(_path: str, _params: dict[str, str]) -> dict[str, Any]:
            raise OSError("offline")

        self.assertEqual(self.run_main(get, "--branch", "summer")[0], 2)

    def test_properties_without_a_project_are_exit_2(self) -> None:
        self.properties.write_text("sonar.organization=paxel\n")
        self.assertEqual(self.run_main(Cloud([], []), "--branch", "summer")[0], 2)

    def test_no_branch_and_no_pull_request_is_exit_2(self) -> None:
        self.assertEqual(self.run_main(Cloud([], []))[0], 2)
        with redirect_stderr(StringIO()):
            self.assertEqual(main([]), 2)

    def test_fetch_sends_the_token_and_decodes_the_answer(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"issues": []}'
        with (
            mock.patch("urllib.request.urlopen", return_value=response) as urlopen,
            mock.patch.dict("os.environ", {"SONAR_TOKEN": "t"}),
        ):
            self.assertEqual(sonar_fetch.fetch("api/issues/search", {"p": "1"}), {"issues": []})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://sonarcloud.io/api/issues/search?p=1")
        self.assertEqual(request.get_header("Authorization"), "Bearer t")

    def test_fetch_refuses_an_answer_that_is_no_object(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"[]"
        with mock.patch("urllib.request.urlopen", return_value=response), self.assertRaises(ValueError):
            sonar_fetch.fetch("api/issues/search", {})


if __name__ == "__main__":
    unittest.main()
