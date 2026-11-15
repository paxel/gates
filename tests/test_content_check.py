import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from content_check import main

H = "a" * 64


class ContentCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_it(self, *args: str) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            code = main(list(args))
        return code, out.getvalue()

    def manifest(self, **kw: object) -> None:
        data: dict[str, object] = {
            "version": "1.0",
            "description": "d",
            "homepage": "h",
            "license": "MIT",
            "url": "u",
            "hash": H,
        }
        data.update(kw)
        (self.root / "x.json").write_text(json.dumps({k: v for k, v in data.items() if v is not None}))

    def test_a_valid_manifest_passes(self) -> None:
        self.manifest()
        self.assertEqual(self.run_it("scoop", str(self.root))[0], 0)

    def test_a_bad_hash_and_a_missing_licence_fail(self) -> None:
        self.manifest(hash="nope", license=None)
        code, out = self.run_it("scoop", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("no license", out)
        self.assertIn("is not a sha256", out)

    def test_architecture_entries_need_url_and_hash(self) -> None:
        self.manifest(url=None, hash=None, architecture={"64bit": {"url": "u"}})
        self.assertEqual(self.run_it("scoop", str(self.root))[0], 1)

    def test_a_skill_needs_name_and_description(self) -> None:
        good = self.root / "ship-it"
        good.mkdir()
        (good / "SKILL.md").write_text("---\nname: ship-it\ndescription: Ship.\n---\n\n# Ship\n")
        self.assertEqual(self.run_it("skills", str(self.root))[0], 0)
        bad = self.root / "walk"
        bad.mkdir()
        (bad / "SKILL.md").write_text("---\nname: other\n---\n")
        code, out = self.run_it("skills", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("is not the directory 'walk'", out)
        self.assertIn("no description", out)

    def test_a_broken_local_link_fails(self) -> None:
        (self.root / "a.apk").write_text("")
        (self.root / "index.html").write_text(
            '<a href="a.apk">ok</a><a href="https://x.org">ext</a><a href="#top">top</a><img src="gone.png">'
        )
        code, out = self.run_it("site", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("gone.png does not exist", out)
        self.assertNotIn("a.apk does not exist", out)

    def test_nothing_to_check_is_exit_2(self) -> None:
        self.assertEqual(self.run_it("scoop", str(self.root))[0], 2)


if __name__ == "__main__":
    unittest.main()
