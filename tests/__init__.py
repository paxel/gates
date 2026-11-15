"""Tests of the gate scripts; run with `python3 -m unittest discover -s tests -t .`."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
