"""The checks of standard.toml, run against one repository's clone and settings.

Every check that applies to a repository is either present or drift. Nothing here talks to
the network: audit.py collects the clone and the settings and passes them in.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import config_check  # noqa: E402
import rust_lints  # noqa: E402

SKIP = {".git", "target", "node_modules", "build", ".dart_tool", "fuzz", "fixtures", ".gates", "vendor"}
SHA = re.compile(r"@[0-9a-f]{40}\s+#\s*\S+")
GATES_USE = re.compile(r"uses:\s*paxel/gates/\.github/workflows/([\w.-]+\.yml)@([0-9a-f]{40})")
ECOSYSTEM = {"rust": "cargo", "dart": "pub", "go": "gomod", "ts": "npm", "python": "uv", "java": "maven"}


@dataclass
class Repo:
    """What the audit knows about one repository."""

    name: str
    root: pathlib.Path
    default_branch: str
    settings: dict[str, Any]
    rules: list[dict[str, Any]]
    stacks: list[str] = field(default_factory=list)
    contents: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Result:
    check: str
    state: str  # "present", "drift" or "n/a"
    detail: str = ""


def walk(root: pathlib.Path, name: str) -> list[pathlib.Path]:
    found = []
    for path in sorted(root.rglob(name)):
        if not any(part in SKIP for part in path.relative_to(root).parts):
            found.append(path)
    return found


def find_stacks(root: pathlib.Path, standard: dict[str, Any]) -> list[str]:
    return [
        str(s["id"])
        for s in standard.get("stacks") or []
        if any(walk(root, m) for m in s.get("manifests") or [])
    ]


def find_contents(root: pathlib.Path, standard: dict[str, Any], stacks: list[str]) -> list[str]:
    if stacks:
        return []
    return [
        str(c["id"])
        for c in standard.get("contents") or []
        if any((root / d).exists() for d in c.get("detect") or [])
    ]


def applies(rule: str, repo: Repo) -> bool:
    if rule == "all":
        return True
    if rule in ("code", "release"):
        return bool(repo.stacks)
    if rule == "content":
        return bool(repo.contents)
    return rule in repo.stacks


def workflows(root: pathlib.Path) -> dict[str, str]:
    d = root / ".github" / "workflows"
    if not d.is_dir():
        return {}
    return {p.name: p.read_text(encoding="utf-8", errors="replace") for p in sorted(d.glob("*.y*ml"))}


def text(root: pathlib.Path, rel: str) -> str | None:
    p = root / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None


# --- one function per detect kind ---------------------------------------------------------

Check = Callable[[Repo, dict[str, Any], dict[str, Any], "Context"], tuple[bool, str]]


@dataclass
class Context:
    gates: pathlib.Path
    latest_sha: str | None
    latest_tag: str | None
    # The latest stable toolchains by stack, e.g. {"rust": "1.99.1"}; a stack without an
    # entry is not checked.
    toolchains: dict[str, str] = field(default_factory=dict)


def k_ruleset(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    types = {r.get("type") for r in repo.rules}
    missing = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} - types
    checks = [
        x["context"]
        for r in repo.rules
        if r.get("type") == "required_status_checks"
        for x in (r.get("parameters") or {}).get("required_status_checks") or []
    ]
    if missing:
        return False, "missing " + ", ".join(sorted(missing))
    if not checks:
        return False, "no required status checks"
    return True, f"{len(checks)} required checks"


def _is(key: str, value: object) -> Callable[[dict[str, Any]], bool]:
    def test(settings: dict[str, Any]) -> bool:
        return bool(settings.get(key) == value)

    return test


SETTING_KEYS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "secret_scanning": _is("secret_scanning", "enabled"),
    "push_protection": _is("push_protection", "enabled"),
    "vulnerability_alerts": _is("vulnerability_alerts", "on"),
    "automated_security_fixes": _is("automated_security_fixes", True),
    "private_vulnerability_reporting": _is("private_vulnerability_reporting", True),
}


def k_setting(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    off = [k for k in d.get("keys") or [] if not SETTING_KEYS[k](repo.settings)]
    return (not off), ("off: " + ", ".join(off)) if off else ""


def k_default_branch(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    want = str(s.get("default_branch", "summer"))
    return repo.default_branch == want, repo.default_branch


def k_file(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    return (repo.root / str(d["path"])).exists(), ""


def k_any_file(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    return any((repo.root / str(p)).exists() for p in d.get("paths") or []), ""


def k_files(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    missing = [str(p) for p in d.get("paths") or [] if not (repo.root / str(p)).exists()]
    return (not missing), ("missing " + ", ".join(missing)) if missing else ""


def k_no_file(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    there = [str(p) for p in d.get("paths") or [] if (repo.root / str(p)).exists()]
    return (not there), ", ".join(there)


def k_agents(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    if not (repo.root / "AGENTS.md").is_file():
        return False, "no AGENTS.md"
    claude = text(repo.root, "CLAUDE.md")
    if claude is None:
        return False, "no CLAUDE.md"
    if claude.strip() != "@AGENTS.md":
        return False, "CLAUDE.md holds more than @AGENTS.md"
    return True, ""


def k_dependabot(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    t = text(repo.root, ".github/dependabot.yml") or text(repo.root, ".github/dependabot.yaml") or ""
    have = set(re.findall(r'package-ecosystem:\s*"?([\w-]+)"?', t))
    need = {"github-actions"} | {ECOSYSTEM[x] for x in repo.stacks}
    if "java" in repo.stacks and "gradle" in have:
        need.discard("maven")
    if "python" in repo.stacks and "pip" in have:
        need.discard("uv")
    missing = sorted(need - have)
    return (not missing), ("missing " + ", ".join(missing)) if missing else ", ".join(sorted(have))


def k_accepted(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    t = text(repo.root, "code-scanning-ignores.toml")
    if t is None:
        return False, "no code-scanning-ignores.toml"
    try:
        entries = tomllib.loads(t).get("IgnoredAlerts") or []
    except ValueError as error:
        return False, f"unreadable: {error}"
    have = {(e.get("tool"), e.get("rule")) for e in entries}
    missing = [a["rule"] for a in s.get("accepted") or [] if (a["tool"], a["rule"]) not in have]
    return (not missing), ("missing " + ", ".join(missing)) if missing else ""


def k_pins(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    missing = []
    for stack in s.get("stacks") or []:
        if stack["id"] not in repo.stacks:
            continue
        pin = str(stack["pin"])
        if stack["id"] == "go":
            ok = all("\ntoolchain go" in (m.read_text(errors="replace")) for m in walk(repo.root, "go.mod"))
        else:
            ok = bool(walk(repo.root, pin)) or (repo.root / pin).exists()
        if not ok:
            missing.append(f"{stack['id']}: {pin}")
    return (not missing), ("missing " + ", ".join(missing)) if missing else ""


def pinned_versions(repo: Repo) -> dict[str, str]:
    found: dict[str, str] = {}
    if "rust" in repo.stacks:
        for p in walk(repo.root, "rust-toolchain.toml"):
            m = re.search(r'channel\s*=\s*"([^"]+)"', p.read_text(errors="replace"))
            if m:
                found["rust"] = m.group(1)
    if "go" in repo.stacks:
        for p in walk(repo.root, "go.mod"):
            m = re.search(r"(?m)^toolchain go(\S+)", p.read_text(errors="replace"))
            if m:
                found["go"] = m.group(1)
    if "dart" in repo.stacks and (repo.root / ".fvmrc").is_file():
        m = re.search(r'"flutter"\s*:\s*"([^"]+)"', (repo.root / ".fvmrc").read_text(errors="replace"))
        if m:
            found["dart"] = m.group(1)
    if "ts" in repo.stacks and (repo.root / ".nvmrc").is_file():
        found["ts"] = (repo.root / ".nvmrc").read_text().strip().lstrip("v")
    return found


def k_pins_current(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    behind = []
    for stack, have in sorted(pinned_versions(repo).items()):
        latest = c.toolchains.get(stack)
        if latest is None:
            continue
        # Node pins name a major or a full version; either must be the latest one.
        if stack == "ts" and "." not in have:
            ok = latest.split(".")[0] == have
        else:
            ok = have == latest
        if not ok:
            behind.append(f"{stack} {have} < {latest}")
    return (not behind), ", ".join(behind)


def k_uses(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    t = workflows(repo.root).get(str(d["file"]))
    if t is None:
        return False, f"no .github/workflows/{d['file']}"
    called = {m.group(1) for m in GATES_USE.finditer(t)}
    if repo.name == "gates":
        # gates calls its own shared workflows by path.
        called |= set(re.findall(r"uses:\s*\./\.github/workflows/([\w.-]+\.yml)", t))
        # Its codeql.yml and fuzz.yml are the shared workflows and its own runs at once.
        if "workflow_call:" in t:
            called.add(str(d["file"]))
    want: list[str] = []
    for w in d.get("workflows") or []:
        if w == "{stack}":
            want += [str(x["workflow"]) for x in s.get("stacks") or [] if x["id"] in repo.stacks]
        else:
            want.append(str(w))
    missing = [w for w in want if w not in called]
    if d.get("schedule") and "schedule:" not in t:
        missing.append("a schedule")
    return (not missing), ("does not call " + ", ".join(missing)) if missing else ""


def k_template(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    have = text(repo.root, str(d["file"]))
    want = (c.gates / str(d["template"])).read_text(encoding="utf-8")
    if have is None:
        return False, f"no {d['file']}"
    return have == want, "" if have == want else f"differs from {d['template']}"


def k_pinned(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    bad = []
    for name, t in workflows(repo.root).items():
        for line in t.splitlines():
            if line.lstrip().startswith("#"):
                continue
            # The action, then whatever follows it on the line (the version comment).
            m = re.search(r"uses:[ \t]*(\S+)", line)
            if not m or m.group(1).startswith(("./", "docker://")):
                continue
            if not SHA.search(line[m.start(1) :]):
                bad.append(f"{name}: {m.group(1)}")
    return (not bad), "; ".join(bad[:5]) + (" …" if len(bad) > 5 else "")


def k_permissions(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    bad = []
    for name, t in workflows(repo.root).items():
        head = t.split("\njobs:")[0]
        # Either "permissions: read-all" on one line, or the block's first entry on the next.
        m = re.search(r"(?m)^permissions:[ \t]*(\S.*)?$", head)
        rest = head[m.end() :] if m else ""
        value = ((m.group(1) or "") if m else "") + " " + " ".join(re.findall(r"(?m)^\s+(\S.*)$", rest)[:1])
        if not m or not re.match(r"\s*(read-all|contents:\s*read|\{\})", value.strip() or "x"):
            bad.append(name)
    return (not bad), ("not contents: read in " + ", ".join(bad)) if bad else ""


def k_gates_version(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    refs = {m.group(2) for t in workflows(repo.root).values() for m in GATES_USE.finditer(t)}
    if repo.name == "gates":
        return True, "gates itself"
    if not refs:
        return False, "calls no shared workflow"
    if c.latest_sha is None:
        return False, "gates has no release yet"
    behind = sorted(r[:7] for r in refs if r != c.latest_sha)
    return (not behind), (f"behind {c.latest_tag}: " + ", ".join(behind)) if behind else str(c.latest_tag)


def k_lint_config(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    problems: list[str] = []
    for stack in s.get("stacks") or []:
        if stack["id"] not in repo.stacks or stack["id"] == "rust":
            continue
        req_file = c.gates / "configs" / str(stack["id"]) / "required.toml"
        reqs = tomllib.loads(req_file.read_text(encoding="utf-8")).get("require") or []
        for manifest in (m for name in stack.get("manifests") or [] for m in walk(repo.root, str(name))):
            problems += config_check.check(manifest.parent, reqs)
    rel = [p.replace(str(repo.root) + "/", "") for p in problems]
    return (not problems), "; ".join(rel[:3]) + (" …" if len(rel) > 3 else "")


def k_rust_lints(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    problems = rust_lints.check(repo.root, rust_lints.required(c.gates / "configs" / "rust" / "lints.toml"))
    return (not problems), f"{len(problems)} lints missing" if problems else ""


BADGE_PATTERNS = [
    ("CI", r"actions/workflows/ci\.yml/badge"),
    ("Security", r"actions/workflows/security\.yml/badge"),
    ("CodeQL", r"actions/workflows/codeql\.yml/badge"),
    ("Scorecard", r"api\.scorecard\.dev/projects/"),
    ("Sonar quality gate", r"sonarcloud\.io/api/project_badges/measure\?[^)\s]*metric=alert_status"),
    ("Coverage", r"\.github(%2F|/)badges(%2F|/)coverage-[\w-]+\.json"),
    ("Fuzz", r"actions/workflows/fuzz\.yml/badge"),
    ("Release", r"img\.shields\.io/github/v/release/"),
    ("License", r"img\.shields\.io/badge/license-"),
    ("panic-free", r"img\.shields\.io/badge/panic--free-"),
    ("unsafe", r"img\.shields\.io/badge/unsafe-"),
]


def badge_kinds(readme: str) -> list[str]:
    """The kind of every badge in the README's head; an unknown one is "other:<alt> <url>"."""
    head = "\n".join(readme.splitlines()[:40])
    kinds = []
    for alt, url in re.findall(r"!\[([^\]]*)\]\(([^)\s]+)", head):
        kind = next((k for k, rx in BADGE_PATTERNS if re.search(rx, url)), None)
        kinds.append(kind or f"other:{alt} {url}")
    return kinds


def k_badges(repo: Repo, d: dict[str, Any], s: dict[str, Any], c: Context) -> tuple[bool, str]:
    readme = text(repo.root, "README.md")
    if readme is None:
        return False, "no README.md"
    b = s.get("badges") or {}
    if repo.contents:
        want = list(b.get("content_row") or [])
    else:
        want = list(b.get("row") or []) + (list(b.get("rust") or []) if "rust" in repo.stacks else [])
    have = badge_kinds(readme)
    row = [k for k in have if not k.startswith("other:")]
    collapsed = [k for i, k in enumerate(row) if k != "Coverage" or i == 0 or row[i - 1] != "Coverage"]
    extra = [k[6:] for k in have if k.startswith("other:")]
    allowed = [str(x).lower() for x in b.get("distribution") or []]
    foreign = [
        u for u in extra if not any(a.replace(" ", "") in u.lower().replace("%20", "") for a in allowed)
    ]
    problems = []
    if collapsed != want:
        missing = [k for k in want if k not in collapsed]
        problems.append(("missing " + ", ".join(missing)) if missing else "out of order")
    if foreign:
        problems.append(f"{len(foreign)} badges outside the row")
    return (not problems), "; ".join(problems)


KINDS: dict[str, Check] = {
    "ruleset": k_ruleset,
    "setting": k_setting,
    "default-branch": k_default_branch,
    "file": k_file,
    "any-file": k_any_file,
    "files": k_files,
    "no-file": k_no_file,
    "agents": k_agents,
    "dependabot": k_dependabot,
    "accepted": k_accepted,
    "pins": k_pins,
    "uses": k_uses,
    "pins-current": k_pins_current,
    "template": k_template,
    "pinned": k_pinned,
    "permissions": k_permissions,
    "gates-version": k_gates_version,
    "lint-config": k_lint_config,
    "rust-lints": k_rust_lints,
    "badges": k_badges,
}


def run(repo: Repo, standard: dict[str, Any], ctx: Context) -> list[Result]:
    results = []
    for check in standard.get("checks") or []:
        if not applies(str(check["applies"]), repo):
            results.append(Result(str(check["id"]), "n/a"))
            continue
        detect = dict(check["detect"])
        ok, detail = KINDS[str(detect["kind"])](repo, detect, standard, ctx)
        results.append(Result(str(check["id"]), "present" if ok else "drift", detail))
    return results
