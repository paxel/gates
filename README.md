# gates

[![CI](https://github.com/paxel/gates/actions/workflows/ci.yml/badge.svg?branch=summer)](https://github.com/paxel/gates/actions/workflows/ci.yml)
[![Security](https://github.com/paxel/gates/actions/workflows/security.yml/badge.svg?branch=summer)](https://github.com/paxel/gates/actions/workflows/security.yml)
[![CodeQL](https://github.com/paxel/gates/actions/workflows/codeql.yml/badge.svg?branch=summer)](https://github.com/paxel/gates/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/paxel/gates/badge)](https://scorecard.dev/viewer/?uri=github.com/paxel/gates)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=paxel_gates&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=paxel_gates)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fpaxel%2Fgates%2Fsummer%2F.github%2Fbadges%2Fcoverage-scripts.json)](coverage-floors.toml)
[![Fuzz](https://github.com/paxel/gates/actions/workflows/fuzz.yml/badge.svg?branch=summer)](https://github.com/paxel/gates/actions/workflows/fuzz.yml)
[![Release](https://img.shields.io/github/v/release/paxel/gates)](https://github.com/paxel/gates/releases)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

The one security and quality standard for every active paxel repository, and the shared
workflows, lint configs, gate scripts and weekly audit that carry it out.

Every repository has every check of the standard, unless it has nothing for that check to
look at. The standard is [`standard.toml`](standard.toml); why it is the way it is, is
[ADR 0001](docs/adr/0001-one-standard.md).

## Using it

A repository copies the caller workflows from [`templates/`](templates/) and pins each
shared workflow to a release:

```yaml
jobs:
  rust:
    uses: paxel/gates/.github/workflows/rust.yml@<sha> # v1.4.1
```

Dependabot's `github-actions` updates propose the next release. The weekly audit opens an
issue in every repository that drifts from the standard.

| Shared workflow    | Does                                                                     |
|--------------------|--------------------------------------------------------------------------|
| `vulns.yml`        | osv-scanner on every lockfile, known vulnerabilities and licences gated  |
| `rust.yml`         | fmt, clippy `-D warnings`, the lint set, tests, coverage ratchet          |
| `dart.yml`         | format, strict analyze, tests, coverage ratchet                           |
| `go.yml`           | gofmt, golangci-lint, tests, coverage ratchet                             |
| `ts.yml`           | prettier, strict typescript-eslint, tests, coverage ratchet               |
| `python.yml`       | ruff, `mypy --strict`, tests, coverage ratchet                            |
| `java.yml`         | formatting, Error Prone, SpotBugs, tests, coverage ratchet                |
| `content.yml`      | the checks for formulas, scoop manifests, skills and static sites         |
| `codeql.yml`       | CodeQL for the repo's languages and its workflows                         |
| `sonar.yml`        | SonarQube Cloud with the measured coverage; fails on unaccepted findings  |
| `fuzz.yml`         | the repo's fuzz targets on a schedule                                     |
| `release-gate.yml` | alerts, SonarQube Cloud findings, vulnerabilities, licences, CHANGELOG    |
| `provenance.yml`   | attestation, Sigstore bundle and SBOM for every release file              |

## Licence

MIT, see [LICENSE](LICENSE).
