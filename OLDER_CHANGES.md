# Older changes

Changes of released versions before the current one, newest first.

## [1.0.0] - 2026-11-16

### Added

- The standard every active repository is held to, with its decisions in ADR 0001
  ([gate-1000](https://github.com/paxel/gates/issues/1)), as one machine-readable
  `standard.toml` ([gate-1001](https://github.com/paxel/gates/issues/2)).
- `vulns.yml`: osv-scanner on every lockfile, blocking on known vulnerabilities, licences
  outside the shared allowlist, exceptions without a reason or date, and stacks whose lockfile
  was not read ([gate-1002](https://github.com/paxel/gates/issues/3),
  [gate-1005](https://github.com/paxel/gates/issues/6)).
- `release-gate.yml`: a release fails on open code-scanning and secret-scanning alerts that
  are not accepted, on vulnerabilities and licences, and without its CHANGELOG section; the
  weekly Security run uses it too ([gate-1003](https://github.com/paxel/gates/issues/4),
  [gate-1014](https://github.com/paxel/gates/issues/15)).
- One coverage ratchet for every stack, with a floor and a badge per measured part
  ([gate-1004](https://github.com/paxel/gates/issues/5)).
- Shared workflows with strict lint configs for Rust, Dart, Go, TypeScript, Python and Java
  ([gate-1006](https://github.com/paxel/gates/issues/7),
  [gate-1007](https://github.com/paxel/gates/issues/8),
  [gate-1008](https://github.com/paxel/gates/issues/9),
  [gate-1009](https://github.com/paxel/gates/issues/10),
  [gate-1010](https://github.com/paxel/gates/issues/11),
  [gate-1011](https://github.com/paxel/gates/issues/12)).
- `content.yml` for formulas, scoop manifests, skills and static sites
  ([gate-1012](https://github.com/paxel/gates/issues/13)).
- `codeql.yml`, `sonar.yml` and `fuzz.yml` for every stack
  ([gate-1013](https://github.com/paxel/gates/issues/14),
  [gate-1021](https://github.com/paxel/gates/issues/22),
  [gate-1020](https://github.com/paxel/gates/issues/21)).
- `provenance.yml`: attestation, Sigstore bundle and CycloneDX SBOM for every release file
  ([gate-1015](https://github.com/paxel/gates/issues/16)).
- Templates for the caller workflows, Dependabot, the ignore files and the badge row
  ([gate-1016](https://github.com/paxel/gates/issues/17)).
- A self-test that runs every gate on a clean fixture, which must pass, and on one with a
  planted finding, which must fail ([gate-1017](https://github.com/paxel/gates/issues/18)).
- A weekly audit of every active repository with a report on Pages and one drift issue per
  repository ([gate-1018](https://github.com/paxel/gates/issues/19)).
