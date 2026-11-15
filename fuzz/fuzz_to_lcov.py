"""Fuzzes the coverage converters: any report text either converts or raises the errors
to_lcov.py's main turns into exit 2, never anything else.

    uv run python fuzz/fuzz_to_lcov.py -max_total_time=300
"""

import pathlib
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parses fuzz input, exactly what is tested

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import atheris  # noqa: E402

with atheris.instrument_imports():
    import to_lcov  # noqa: E402


def test_one(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    for convert in (to_lcov.from_go, to_lcov.from_jacoco):
        try:
            files = convert(text)
        except (ValueError, ET.ParseError):
            continue
        out = to_lcov.lcov(files)
        if out and not out.endswith("end_of_record\n"):
            raise AssertionError("lcov output without a closing record")


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()
