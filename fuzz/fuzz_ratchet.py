"""Fuzzes the ratchet's floor rewrite and lcov reading: rewriting one part's floor never
touches another part, and malformed lcov only ever raises ValueError (exit 2).

    uv run python fuzz/fuzz_ratchet.py -max_total_time=300
"""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import atheris  # noqa: E402

with atheris.instrument_imports():
    import coverage_ratchet  # noqa: E402

OTHER = '[[parts]]\nname = "other"\nlcov = "o.lcov"\nfloor = 12.34\n'


def test_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(12)
    lcov = fdp.ConsumeUnicodeNoSurrogates(4096)
    text = f'[[parts]]\nname = "{name}"\nlcov = "x"\nfloor = 1.00\n' + OTHER
    out = coverage_ratchet.raise_floor(text, name, 99.0)
    if name != "other" and "floor = 12.34" not in out:
        raise AssertionError("raising one part's floor changed another part")
    with tempfile.NamedTemporaryFile("w", suffix=".lcov", encoding="utf-8") as f:
        f.write(lcov)
        f.flush()
        try:
            coverage_ratchet.measure(pathlib.Path(f.name), pathlib.Path("/"), [])
        except ValueError:
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()
