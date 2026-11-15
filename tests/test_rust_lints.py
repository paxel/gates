import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from rust_lints import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINTS = ROOT / "configs" / "rust" / "lints.toml"
SET = (LINTS.read_text().split("\n[lints.rust]\n", 1)[1]).strip()


class RustLintsTest(unittest.TestCase):
    def check(self, files: dict[str, str]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--root", str(root), "--lints", str(LINTS)])
            return code, out.getvalue()

    def test_a_crate_with_the_set_passes(self) -> None:
        code, _ = self.check({"Cargo.toml": f'[package]\nname = "a"\n\n[lints.rust]\n{SET}\n'})
        self.assertEqual(code, 0)

    def test_a_crate_without_lints_fails_on_every_one(self) -> None:
        code, out = self.check({"Cargo.toml": '[package]\nname = "a"\n'})
        self.assertEqual(code, 1)
        self.assertIn("clippy::unwrap_used is not denied", out)
        self.assertIn("rust::unsafe_code is not denied", out)
        self.assertIn("12 lints missing", out)

    def test_warn_is_not_enough(self) -> None:
        text = f'[package]\nname = "a"\n\n[lints.rust]\n{SET}\n'.replace('panic = "deny"', 'panic = "warn"')
        code, out = self.check({"Cargo.toml": text})
        self.assertEqual(code, 1)
        self.assertIn("clippy::panic is not denied", out)

    def test_members_use_the_workspace_lints(self) -> None:
        files = {
            "Cargo.toml": f'[workspace]\nmembers = ["crates/a"]\n\n[workspace.lints.rust]\n{SET}\n'.replace(
                "[lints.clippy]", "[workspace.lints.clippy]"
            ),
            "crates/a/Cargo.toml": '[package]\nname = "a"\n\n[lints]\nworkspace = true\n',
        }
        self.assertEqual(self.check(files)[0], 0)

    def test_fuzz_crates_are_skipped(self) -> None:
        files = {
            "Cargo.toml": f'[package]\nname = "a"\n\n[lints.rust]\n{SET}\n',
            "fuzz/Cargo.toml": '[package]\nname = "a-fuzz"\n',
        }
        self.assertEqual(self.check(files)[0], 0)


if __name__ == "__main__":
    unittest.main()
