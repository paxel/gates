# 1. One standard for every active repository

Date: 2026-11-15

## Status

Accepted.

## Context

An audit of the 21 active paxel repositories on 2026-11-15 found every concern solved in
several ways: six vulnerability scanners, five ways to keep coverage, badges from none to
nineteen, releases gated on alerts in five repositories and on nothing in others. Each was
added by a different agent session, and each looked green. The maintainer is a single person;
reviews, a second approver and a best-practices badge cannot exist.

## Decision

Every active repository has every check of the standard, unless it has nothing for that check
to look at (no such stack). The standard is `standard.toml`.

**Where the gates live (Q1, Q17).** Shared workflows in this public repository, pinned by SHA
(G4: semver tags, Dependabot bumps). An audit covers what workflows cannot hold: settings,
files, badges, lints and the Scorecard copy.

**Vulnerabilities and licences (Q2, Q3, G6, G7).** osv-scanner with `osv_gate.py` on every
stack; cargo audit, cargo deny, govulncheck and npm audit are removed. One licence allowlist:
MIT, MIT-0, 0BSD, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause,
ISC, Zlib, BSL-1.0, Unicode-3.0, CC0-1.0, Unlicense, bzip2-1.0.6, MPL-2.0, OFL-1.1,
Ubuntu-font-1.0. Advisory and licence exceptions carry a reason and a date.

**Coverage (Q4).** One ratchet script; one floor per measured part, raised to the measured
value minus 0.1; CI only checks; a badge per floor.

**Alerts (Q5, Q6).** The release and the weekly Security run fail on every open code-scanning
alert, of any tool and severity, and every open secret-scanning alert that the repository's
`code-scanning-ignores.toml` does not accept with a reason and a date. An accepted alert that
is in a file names that file, and the entry covers that file only; an entry without a file is
for an alert about the repository as a whole. Dependabot alerts do not count; osv-scanner
covers the same advisories.

**SonarQube Cloud findings (1.1.0).** SonarQube Cloud's quality gate looks at new code only, so
gates 1.0.0 was released with 32 open issues and a security rating of E. Since 1.1.0 every
open issue, of any type and severity, and every security hotspot to review counts like an
alert: it fails the release, the weekly Security run and CI's sonar job unless
`code-scanning-ignores.toml` accepts it, with tool "SonarQube Cloud", its rule and its file.
Nothing is marked as false positive, accepted or safe in SonarQube Cloud's web UI: the reason
and the date live in the repository. Since 1.2.0 the quality gate's own verdict does not fail
the sonar job, because it cannot see what the file accepts; the findings alone decide.

**Releases (Q7, Q8).** Every release file gets a build provenance attestation, the Sigstore
bundle and a CycloneDX SBOM; npm and PyPI packages get their registry's provenance;
registry-only libraries attach their packages to the GitHub release.

**README (Q9).** One badge row in a fixed order: CI · Security · CodeQL · Scorecard · Sonar
quality gate · Coverage (per floor) · Fuzz · Release · License; Rust adds panic-free and
unsafe; then distribution badges; nothing else.

**Repositories without app code (Q10).** agent-skills, fdroid, homebrew-tap and scoop-bucket
get everything that applies, with a CI that checks what they hold.

**Branch and files (Q11, Q12).** The default branch is `summer`. `AGENTS.md` holds the rules,
`CLAUDE.md` holds only `@AGENTS.md`, plus `CONTEXT.md`, `docs/adr/` and
`docs/agents/{issue-tracker,triage-labels,ticket-ids}.md`.

**Lints and toolchains (Q13, Q14, Q15).** wipTracker's Rust lint set in every crate's
Cargo.toml; one strict lint config per stack; one toolchain pin file per stack, the only
source of the version.

**Audit (Q16).** A weekly workflow here checks every repository, publishes the report on
Pages, opens or updates one issue per drifting repository and goes red.

**Rollout (Q18, Q19).** gates first, pixpixpix as the pilot, then the most urgent findings,
the repositories without app code last; per repository a short grill, tickets in a `gates`
milestone, a long walk and a pull request the maintainer merges.

**Self-test (G8).** Every gate runs on a fixture twice, clean (must pass) and with a planted
finding (must fail).

**Single maintainer.** Scorecard's Code-Review, CII-Best-Practices and BranchProtection
findings are accepted in every repository with that reason; Renovate is not used.

## Consequences

- A shared workflow checks gates out at `job.workflow_sha`, so its scripts are those of the
  pinned commit.
- `GITHUB_TOKEN` cannot read secret-scanning alerts. The release gate needs the secret
  `GATES_ALERTS_TOKEN` (fine-grained, Secret scanning alerts: read) in every repository and
  fails without it. The audit needs `GATES_AUDIT_TOKEN` (read-only, plus Issues: read and
  write to open the drift issues).
- A job that calls a reusable workflow cannot be allowed to fail, so the red fixtures run the
  composite actions as steps.
- Every repository's required checks change their names when its callers move to the shared
  workflows; the ruleset is updated in the same step.
