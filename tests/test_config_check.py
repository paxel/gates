import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from config_check import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs"
PINS = {
    "go": {"go.mod": "module x\n\ngo 1.25\n\ntoolchain go1.25.4\n"},
}


class ConfigCheckTest(unittest.TestCase):
    def run_check(self, stack: str, files: dict[str, str]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                (pathlib.Path(tmp) / name).write_text(text)
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--stack", stack, "--dir", tmp, "--configs", str(CONFIGS)])
            return code, out.getvalue()

    def test_every_stack_config_passes_its_own_requirements(self) -> None:
        shipped = {
            "dart": {"analysis_options.yaml": "dart/analysis_options.yaml"},
            "go": {".golangci.yml": "go/.golangci.yml"},
            "ts": {"eslint.config.mjs": "ts/eslint.config.mjs", "tsconfig.json": "ts/tsconfig.json"},
            "python": {"ruff.toml": "python/ruff.toml", "pyproject.toml": "python/pyproject-mypy.toml"},
            "java": {"pom.xml": "java/pom-snippet.xml"},
        }
        for stack, files in shipped.items():
            with self.subTest(stack=stack):
                texts = {k: (CONFIGS / v).read_text() for k, v in files.items()}
                texts.update(PINS.get(stack, {}))
                code, out = self.run_check(stack, texts)
                self.assertEqual(code, 0, out)

    def test_a_missing_file_fails(self) -> None:
        code, out = self.run_check("dart", {})
        self.assertEqual(code, 1)
        self.assertIn("none of analysis_options.yaml exists", out)

    def test_a_missing_setting_fails(self) -> None:
        text = (CONFIGS / "dart" / "analysis_options.yaml").read_text().replace("strict-casts: true", "")
        code, out = self.run_check("dart", {"analysis_options.yaml": text})
        self.assertEqual(code, 1)
        self.assertIn("strict-casts", out)

    def test_an_unknown_stack_is_exit_2(self) -> None:
        self.assertEqual(self.run_check("cobol", {})[0], 2)


if __name__ == "__main__":
    unittest.main()
