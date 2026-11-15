import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from coverage_ratchet import main


def lcov(*files: tuple[str, int, int]) -> str:
    return "".join(f"SF:{p}\nLF:{lf}\nLH:{lh}\nend_of_record\n" for p, lf, lh in files)


class CoverageRatchetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self) -> None:
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def write(self, floor: float, *files: tuple[str, int, int], exclude: str = "") -> None:
        (self.root / "core.lcov").write_text(lcov(*files))
        (self.root / "coverage-floors.toml").write_text(
            f'[[parts]]\nname = "core"\nlcov = "core.lcov"\nfloor = {floor}\n{exclude}'
            '\n[[parts]]\nname = "gui"\nlcov = "gui.lcov"\nfloor = 50.00\n'
        )
        (self.root / "gui.lcov").write_text(lcov(("src/gui.rs", 10, 5)))

    def run_it(self, *args: str) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            code = main(
                [
                    "--floors",
                    str(self.root / "coverage-floors.toml"),
                    "--badges",
                    str(self.root / "badges"),
                    *args,
                ]
            )
        return code, out.getvalue()

    def test_below_the_floor_fails(self) -> None:
        self.write(80.0, ("src/a.rs", 100, 70))
        code, out = self.run_it("--check")
        self.assertEqual(code, 1)
        self.assertIn("coverage core: 70.00% is below the floor of 80.00%", out)

    def test_check_never_writes(self) -> None:
        self.write(80.0, ("src/a.rs", 100, 95))
        self.assertEqual(self.run_it("--check")[0], 0)
        self.assertIn("floor = 80.0", (self.root / "coverage-floors.toml").read_text())
        self.assertFalse((self.root / "badges").exists())

    def test_a_rise_raises_only_that_floor_and_writes_its_badge(self) -> None:
        self.write(80.0, ("src/a.rs", 100, 95))
        code, out = self.run_it()
        self.assertEqual(code, 0)
        text = (self.root / "coverage-floors.toml").read_text()
        self.assertIn("floor = 94.90", text)
        self.assertIn("floor = 50.00", text)
        badge = json.loads((self.root / "badges" / "coverage-core.json").read_text())
        self.assertEqual(badge["message"], "94.90%")
        self.assertIn("floor raised from 80.00% to 94.90%", out)

    def test_excluded_files_are_left_out(self) -> None:
        self.write(
            90.0, ("src/a.rs", 100, 95), ("src/beeper.rs", 100, 0), exclude='exclude = ["src/beeper.rs"]\n'
        )
        self.assertEqual(self.run_it("--check")[0], 0)

    def test_an_empty_measure_fails(self) -> None:
        self.write(10.0)
        code, out = self.run_it("--check")
        self.assertEqual(code, 1)
        self.assertIn("measures no line", out)

    def test_a_missing_lcov_is_exit_2(self) -> None:
        self.write(10.0, ("a", 1, 1))
        (self.root / "gui.lcov").unlink()
        self.assertEqual(self.run_it("--check")[0], 2)

    def test_no_parts_fails(self) -> None:
        (self.root / "coverage-floors.toml").write_text("")
        self.assertEqual(self.run_it("--check")[0], 1)


if __name__ == "__main__":
    unittest.main()
