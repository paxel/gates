"""The red Python fixture of paxel/gates: the planted finding is eval on input, which ruff's
security rules report (S307), so the Python gate must fail."""


def add(a: str, b: str) -> int:
    """Add two numbers given as text."""
    return int(eval(a)) + int(eval(b))
