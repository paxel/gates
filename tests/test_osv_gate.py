import datetime
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from typing import Any
from unittest import mock

import osv_gate
from osv_gate import main, pub_licences

ROOT = pathlib.Path(__file__).resolve().parent.parent
TODAY = datetime.date(2026, 11, 15)


def vuln(vid: str, informational: str | None = None) -> dict[str, Any]:
    specific = {"informational": informational} if informational else {}
    return {"id": vid, "summary": f"{vid} summary", "affected": [{"database_specific": specific}]}


class OsvGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "Cargo.toml").write_text("[package]\nname = 'x'\n")
        (self.root / "Cargo.lock").write_text("")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def results(self, packages: list[dict[str, Any]], source: str = "Cargo.lock") -> dict[str, Any]:
        return {"results": [{"source": {"path": str(self.root / source)}, "packages": packages}]}

    def gate(self, data: dict[str, Any], *extra: str) -> tuple[int, str]:
        path = self.root / "osv.json"
        path.write_text(json.dumps(data))
        out = StringIO()
        with redirect_stdout(out):
            code = main(
                [
                    "--results",
                    str(path),
                    "--root",
                    str(self.root),
                    "--standard",
                    str(ROOT / "standard.toml"),
                    *extra,
                ],
                today=TODAY,
            )
        return code, out.getvalue()

    def pkg(self, **kw: Any) -> dict[str, Any]:
        return {"package": {"name": "paste", "version": "1.0.15", "ecosystem": "crates.io"}, **kw}

    def test_clean_scan_passes(self) -> None:
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 0)
        self.assertIn("0 findings, 0 of them blocking", out)

    def test_a_vulnerability_blocks(self) -> None:
        code, out = self.gate(self.results([self.pkg(vulnerabilities=[vuln("RUSTSEC-1")])]))
        self.assertEqual(code, 1)
        self.assertIn("VULNERABILITY: RUSTSEC-1 paste 1.0.15", out)

    def test_an_unmaintained_notice_blocks_only_when_strict(self) -> None:
        data = self.results([self.pkg(vulnerabilities=[vuln("RUSTSEC-2", "unmaintained")])])
        self.assertEqual(self.gate(data)[0], 0)
        self.assertEqual(self.gate(data, "--strict")[0], 1)

    def test_a_licence_violation_blocks(self) -> None:
        code, out = self.gate(self.results([self.pkg(licenses=["GPL-3.0"], license_violations=["GPL-3.0"])]))
        self.assertEqual(code, 1)
        self.assertIn("LICENCE: paste 1.0.15", out)

    def pub(self, name: str = "yaml", version: str = "3.1.3") -> dict[str, Any]:
        return {
            "package": {"name": name, "version": version, "ecosystem": "Pub"},
            "licenses": ["UNKNOWN"],
            "license_violations": ["UNKNOWN"],
        }

    def pub_gate(
        self, answer: tuple[list[str], str], *packages: dict[str, Any]
    ) -> tuple[int, str, mock.Mock]:
        (self.root / "pubspec.lock").write_text("")
        lookup = mock.Mock(return_value=answer)
        with mock.patch.object(osv_gate, "pub_licences", lookup):
            code, out = self.gate(self.results(list(packages or [self.pub()]), "pubspec.lock"))
        return code, out, lookup

    def test_an_unknown_pub_licence_that_pub_dev_names_as_allowed_passes(self) -> None:
        code, out, lookup = self.pub_gate((["mit"], ""))
        self.assertEqual(code, 0, out)
        lookup.assert_called_once_with("yaml", "3.1.3")

    def test_a_pub_licence_outside_the_allowlist_blocks(self) -> None:
        code, out, _ = self.pub_gate((["mit", "gpl-3.0"], ""))
        self.assertEqual(code, 1)
        self.assertIn("LICENCE: yaml 3.1.3", out)
        self.assertIn("gpl-3.0 (pub.dev)", out)
        self.assertNotIn("mit,", out)

    def test_no_answer_from_pub_dev_blocks(self) -> None:
        code, out, _ = self.pub_gate(([], "no answer from pub.dev: timed out"))
        self.assertEqual(code, 1)
        self.assertIn("UNKNOWN, no answer from pub.dev: timed out", out)

    def test_a_pub_version_is_looked_up_once(self) -> None:
        _, _, lookup = self.pub_gate((["bsd-3-clause"], ""), self.pub(), self.pub())
        lookup.assert_called_once_with("yaml", "3.1.3")

    def test_an_unknown_licence_of_another_ecosystem_is_not_looked_up(self) -> None:
        lookup = mock.Mock(return_value=(["mit"], ""))
        pkg = self.pkg(licenses=["UNKNOWN"], license_violations=["UNKNOWN"])
        with mock.patch.object(osv_gate, "pub_licences", lookup):
            code, out = self.gate(self.results([pkg]))
        self.assertEqual(code, 1)
        self.assertIn("LICENCE: paste 1.0.15", out)
        lookup.assert_not_called()

    def test_a_named_pub_licence_outside_the_allowlist_is_not_looked_up(self) -> None:
        pkg = {**self.pub(), "licenses": ["GPL-3.0"], "license_violations": ["GPL-3.0"]}
        code, out, lookup = self.pub_gate((["mit"], ""), pkg)
        self.assertEqual(code, 1)
        self.assertIn("GPL-3.0", out)
        lookup.assert_not_called()

    def answer(self, body: bytes) -> mock.MagicMock:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = body
        return response

    def test_pub_dev_tags_give_the_licences_without_the_classifications(self) -> None:
        body = json.dumps({"tags": ["sdk:dart", "license:mit", "license:fsf-libre", "license:osi-approved"]})
        with mock.patch("urllib.request.urlopen", return_value=self.answer(body.encode())) as urlopen:
            self.assertEqual(pub_licences("yaml", "3.1.3+1"), (["mit"], ""))
        self.assertEqual(
            urlopen.call_args.args[0], "https://pub.dev/api/packages/yaml/versions/3.1.3%2B1/score"
        )

    def test_an_obsolete_pub_version_names_no_licence(self) -> None:
        body = json.dumps({"tags": ["publisher:tools.dart.dev", "is:obsolete"]})
        with mock.patch("urllib.request.urlopen", return_value=self.answer(body.encode())):
            licences, reason = pub_licences("yaml", "3.1.0")
        self.assertEqual(licences, [])
        self.assertIn("no licence", reason)

    def test_an_unreadable_pub_dev_answer_names_no_licence(self) -> None:
        for effect in (OSError("timed out"), None):
            with mock.patch(
                "urllib.request.urlopen", side_effect=effect, return_value=self.answer(b"<html>")
            ):
                licences, reason = pub_licences("yaml", "3.1.3")
            self.assertEqual(licences, [])
            self.assertTrue(reason)

    def test_the_repos_own_package_has_no_licence_to_check(self) -> None:
        own = {
            "package": {"name": "x", "version": "0.1.0"},
            "licenses": ["UNKNOWN"],
            "license_violations": ["UNKNOWN"],
        }
        self.assertEqual(self.gate(self.results([own]))[0], 0)

    def test_the_fuzz_crate_is_the_repos_own_package_too(self) -> None:
        sub = self.root / "fuzz"
        sub.mkdir()
        (sub / "Cargo.toml").write_text('[package]\nname = "x-fuzz"\n')
        (sub / "Cargo.lock").write_text("")
        own = {
            "package": {"name": "x-fuzz", "version": "0.0.0"},
            "licenses": ["UNKNOWN"],
            "license_violations": ["UNKNOWN"],
        }
        data = self.results([self.pkg()])
        data["results"].append({"source": {"path": str(sub / "Cargo.lock")}, "packages": [own]})
        self.assertEqual(self.gate(data)[0], 0)

    def test_an_acceptance_in_fuzz_needs_its_reason_and_date_too(self) -> None:
        sub = self.root / "fuzz"
        sub.mkdir()
        (sub / "osv-scanner.toml").write_text('[[IgnoredVulns]]\nid = "RUSTSEC-1"\n')
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 1)
        self.assertIn("BAD ENTRY: fuzz/osv-scanner.toml", out)

    def test_a_manifest_without_a_scanned_lockfile_blocks(self) -> None:
        sub = self.root / "app"
        sub.mkdir()
        (sub / "pubspec.yaml").write_text("name: app\n")
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 1)
        self.assertIn("NOT SCANNED: app/pubspec.yaml", out)

    def test_an_excluded_directory_is_not_asked_for_a_lockfile(self) -> None:
        sub = self.root / "fixtures" / "go"
        sub.mkdir(parents=True)
        (sub / "go.mod").write_text("module x\n")
        self.assertEqual(self.gate(self.results([self.pkg()]))[0], 1)
        self.assertEqual(self.gate(self.results([self.pkg()]), "--exclude", "fixtures")[0], 0)

    def test_a_workspace_member_uses_the_root_lockfile(self) -> None:
        member = self.root / "crates" / "core"
        member.mkdir(parents=True)
        (member / "Cargo.toml").write_text("")
        self.assertEqual(self.gate(self.results([self.pkg()]))[0], 0)

    def test_container_paths_map_onto_the_workspace(self) -> None:
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            data = {"results": [{"source": {"path": "/github/workspace/Cargo.lock"}, "packages": []}]}
            self.assertEqual(self.gate(data)[0], 0)
        finally:
            os.chdir(cwd)

    def test_nothing_scanned_blocks(self) -> None:
        code, out = self.gate({"results": []})
        self.assertEqual(code, 1)
        self.assertIn("NOT SCANNED: Cargo.toml", out)

    def test_an_ignore_needs_a_reason_and_a_date(self) -> None:
        (self.root / "osv-scanner.toml").write_text('[[IgnoredVulns]]\nid = "RUSTSEC-3"\n')
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 1)
        self.assertIn("IgnoredVulns RUSTSEC-3: no reason, no ignoreUntil date", out)

    def test_a_passed_date_blocks(self) -> None:
        (self.root / "osv-scanner.toml").write_text(
            '[[IgnoredVulns]]\nid = "RUSTSEC-3"\nignoreUntil = 2026-11-14\nreason = "r"\n'
        )
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 1)
        self.assertIn("ignoreUntil 2026-11-14 has passed", out)

    def test_a_licence_exception_needs_reason_and_effective_until(self) -> None:
        (self.root / "osv-scanner.toml").write_text(
            '[[PackageOverrides]]\nname = "webpki-roots"\necosystem = "crates.io"\nlicense.ignore = true\n'
        )
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 1)
        self.assertIn("PackageOverrides webpki-roots crates.io: no reason, no effectiveUntil date", out)

    def test_a_complete_entry_is_accepted(self) -> None:
        (self.root / "osv-scanner.toml").write_text(
            '[[PackageOverrides]]\nname = "w"\nlicense.ignore = true\n'
            'effectiveUntil = 2027-05-14\nreason = "r"\n'
        )
        code, out = self.gate(self.results([self.pkg()]))
        self.assertEqual(code, 0)
        self.assertIn("accepted (reported only): osv-scanner.toml: PackageOverrides w until 2027-05-14", out)

    def test_the_allowlist_comes_from_the_standard(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["--allowlist", str(ROOT / "standard.toml")]), 0)
        self.assertIn("MIT,MIT-0,0BSD,Apache-2.0", out.getvalue())
        self.assertIn("MPL-2.0", out.getvalue())
        self.assertNotIn("WITH", out.getvalue())

    def test_unreadable_results_are_exit_2(self) -> None:
        code = main(["--results", str(self.root / "missing.json"), "--standard", str(ROOT / "standard.toml")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
