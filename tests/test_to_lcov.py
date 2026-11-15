import unittest

from to_lcov import from_go, from_jacoco, lcov

GO = """mode: set
example.com/x/a.go:3.10,5.2 2 1
example.com/x/a.go:7.10,9.2 3 0
example.com/x/b.go:1.1,2.2 1 0
example.com/x/b.go:1.1,2.2 1 1
"""

JACOCO = """<?xml version="1.0"?>
<report name="x"><package name="io/x">
<sourcefile name="A.java"><counter type="INSTRUCTION" missed="9" covered="1"/>
<counter type="LINE" missed="2" covered="8"/></sourcefile>
</package></report>
"""


class ToLcovTest(unittest.TestCase):
    def test_go_counts_statements_per_file(self) -> None:
        files = from_go(GO)
        self.assertEqual(files["example.com/x/a.go"], (5, 2))
        self.assertEqual(files["example.com/x/b.go"], (1, 1))

    def test_jacoco_counts_lines(self) -> None:
        self.assertEqual(from_jacoco(JACOCO), {"io/x/A.java": (10, 8)})

    def test_lcov_output(self) -> None:
        self.assertEqual(lcov({"a": (2, 1)}), "SF:a\nLF:2\nLH:1\nend_of_record\n")


if __name__ == "__main__":
    unittest.main()
