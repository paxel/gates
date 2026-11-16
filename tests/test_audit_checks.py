import pathlib
import sys
import tempfile
import tomllib
import unittest
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "audit"))

import checks  # noqa: E402

STANDARD = tomllib.loads((ROOT / "standard.toml").read_text())
SHA = "a" * 40
CTX = checks.Context(gates=ROOT, latest_sha=SHA, latest_tag="v1.0.0")
GOOD_RULES: list[dict[str, Any]] = [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request"},
    {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ci"}]}},
]


class AuditChecksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, files: dict[str, str]) -> None:
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def repo(self, **kw: Any) -> checks.Repo:
        r = checks.Repo(
            name="x",
            root=self.root,
            default_branch=kw.get("branch", "summer"),
            settings=kw.get("settings", {}),
            rules=kw.get("rules", GOOD_RULES),
        )
        r.stacks = checks.find_stacks(self.root, STANDARD)
        r.contents = checks.find_contents(self.root, STANDARD, r.stacks)
        return r

    def results(self, repo: checks.Repo) -> dict[str, checks.Result]:
        return {r.check: r for r in checks.run(repo, STANDARD, CTX)}

    def test_stacks_and_contents_are_found(self) -> None:
        self.write({"Cargo.toml": "[package]\nname='x'\n", "web/package.json": "{}"})
        self.assertEqual(self.repo().stacks, ["rust", "ts"])
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        (pathlib.Path(other.name) / "bucket").mkdir()
        r = checks.Repo("b", pathlib.Path(other.name), "summer", {}, [])
        self.assertEqual(checks.find_contents(r.root, STANDARD, []), ["scoop"])

    def test_a_check_for_a_missing_stack_does_not_apply(self) -> None:
        self.write({"pyproject.toml": "[project]\nname='x'\n"})
        res = self.results(self.repo())
        self.assertEqual(res["rust-lints"].state, "n/a")
        self.assertEqual(res["content-ci"].state, "n/a")
        self.assertEqual(res["ci"].state, "drift")

    def test_ruleset_needs_all_four_rules(self) -> None:
        self.assertEqual(self.results(self.repo())["ruleset"].state, "present")
        res = self.results(self.repo(rules=GOOD_RULES[:2]))["ruleset"]
        self.assertEqual(res.state, "drift")
        self.assertIn("pull_request", res.detail)

    def test_claude_md_must_only_point_at_agents_md(self) -> None:
        self.write({"AGENTS.md": "# rules\n", "CLAUDE.md": "@AGENTS.md\nmore\n"})
        self.assertEqual(self.results(self.repo())["agents-md"].state, "drift")
        self.write({"CLAUDE.md": "@AGENTS.md\n"})
        self.assertEqual(self.results(self.repo())["agents-md"].state, "present")

    def test_ci_must_call_the_stack_and_vulns_workflows(self) -> None:
        self.write({"Cargo.toml": "[package]\nname='x'\n"})
        ci = (
            "jobs:\n  v:\n    uses: paxel/gates/.github/workflows/vulns.yml@" + SHA + " # v1.0.0\n"
            "  r:\n    uses: paxel/gates/.github/workflows/rust.yml@" + SHA + " # v1.0.0\n"
        )
        self.write({".github/workflows/ci.yml": ci})
        res = self.results(self.repo())
        self.assertEqual(res["ci"].state, "present")
        self.assertEqual(res["gates-current"].state, "present")
        self.write({".github/workflows/ci.yml": ci.replace("rust.yml", "dart.yml")})
        self.assertIn("rust.yml", self.results(self.repo())["ci"].detail)

    def test_an_old_gates_pin_is_drift(self) -> None:
        self.write(
            {
                ".github/workflows/ci.yml": "uses: paxel/gates/.github/workflows/vulns.yml@"
                + "b" * 40
                + " # v0.9.0\n"
            }
        )
        res = self.results(self.repo())["gates-current"]
        self.assertEqual(res.state, "drift")
        self.assertIn("behind v1.0.0", res.detail)

    def test_actions_must_be_pinned_with_a_version_comment(self) -> None:
        self.write(
            {
                ".github/workflows/a.yml": "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
            }
        )
        res = self.results(self.repo())
        self.assertEqual(res["pinned"].state, "drift")
        self.assertEqual(res["permissions"].state, "present")
        self.write(
            {
                ".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@"
                + SHA
                + " # v7\n"
            }
        )
        res = self.results(self.repo())
        self.assertEqual(res["pinned"].state, "present")
        self.assertEqual(res["permissions"].state, "drift")

    def test_permissions_on_one_line_count_too(self) -> None:
        for head, state in (
            ("permissions: read-all\n", "present"),
            ("permissions:   {}\n", "present"),
            ("permissions: write-all\n", "drift"),
            ("permissions:\n  contents: write\n", "drift"),
            ("on: push\n\npermissions:\n  contents: read\n", "present"),
        ):
            with self.subTest(head=head):
                self.write({".github/workflows/a.yml": head + "jobs:\n  a:\n    steps: []\n"})
                self.assertEqual(self.results(self.repo())["permissions"].state, state)

    def test_the_scorecard_copy_must_match_the_template(self) -> None:
        template = (ROOT / "templates" / "workflows" / "scorecard.yml").read_text()
        self.write({".github/workflows/scorecard.yml": template})
        self.assertEqual(self.results(self.repo())["scorecard"].state, "present")
        self.write({".github/workflows/scorecard.yml": template + "# changed\n"})
        self.assertEqual(self.results(self.repo())["scorecard"].state, "drift")

    def test_accepted_scorecard_findings(self) -> None:
        self.write(
            {"code-scanning-ignores.toml": '[[IgnoredAlerts]]\ntool = "Scorecard"\nrule = "CodeReviewID"\n'}
        )
        res = self.results(self.repo())["code-scanning-ignores"]
        self.assertEqual(res.state, "drift")
        self.assertIn("BranchProtectionID", res.detail)

    def test_dependabot_covers_the_stacks(self) -> None:
        self.write(
            {
                "go.mod": "module x\n",
                ".github/dependabot.yml": "updates:\n  - package-ecosystem: github-actions\n",
            }
        )
        res = self.results(self.repo())["dependabot"]
        self.assertEqual(res.state, "drift")
        self.assertIn("gomod", res.detail)

    def test_badges_in_order_and_nothing_else(self) -> None:
        self.write({"Cargo.toml": "[package]\nname='x'\n"})
        badges = (ROOT / "templates" / "badges.md").read_text().replace("REPO", "x")
        self.write({"README.md": badges})
        self.assertEqual(self.results(self.repo())["badges"].state, "present")
        self.write({"README.md": badges + "![size](https://img.shields.io/github/repo-size/paxel/x)\n"})
        res = self.results(self.repo())["badges"]
        self.assertEqual(res.state, "drift")
        self.assertIn("outside the row", res.detail)
        self.write({"README.md": badges + "![crates.io](https://img.shields.io/crates/v/x)\n"})
        self.assertEqual(self.results(self.repo())["badges"].state, "present")

    def test_an_old_toolchain_pin_is_drift(self) -> None:
        self.write(
            {
                "Cargo.toml": "[package]\nname='x'\n",
                "rust-toolchain.toml": '[toolchain]\nchannel = "1.98.0"\n',
            }
        )
        ctx = checks.Context(gates=ROOT, latest_sha=SHA, latest_tag="v1.0.0", toolchains={"rust": "1.99.1"})
        res = {r.check: r for r in checks.run(self.repo(), STANDARD, ctx)}["toolchain-current"]
        self.assertEqual(res.state, "drift")
        self.assertIn("rust 1.98.0 < 1.99.1", res.detail)

    def test_settings_and_branch(self) -> None:
        on = {
            "secret_scanning": "enabled",
            "push_protection": "enabled",
            "vulnerability_alerts": "on",
            "automated_security_fixes": True,
            "private_vulnerability_reporting": True,
        }
        res = self.results(self.repo(settings=on, branch="main"))
        self.assertEqual(res["private-vulnerability-reporting"].state, "present")
        self.assertEqual(res["default-branch"].state, "drift")


if __name__ == "__main__":
    unittest.main()
