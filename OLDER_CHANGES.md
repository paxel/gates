# Older changes

Changes of released versions before the current one, newest first.

## [1.1.1] - 2026-11-17

### Fixed

- SonarQube Cloud shows the coverage of a Rust repository again: `rust.yml` names the covered
  files relative to the repository, not with the runner's absolute paths
  ([gate-1032](https://github.com/paxel/gates/issues/41)).

## [1.1.0] - 2026-11-16

### Added

- The alert gate counts SonarQube Cloud's open issues, of any type and severity, and its
  security hotspots to review; each blocks unless `code-scanning-ignores.toml` accepts it with
  tool "SonarQube Cloud", its rule and its file
  ([gate-1023](https://github.com/paxel/gates/issues/28)).
- `release-gate.yml` reads the SonarQube Cloud findings of every caller that has a
  `sonar-project.properties` and fails when they cannot be read; the weekly Security run
  uses it too ([gate-1024](https://github.com/paxel/gates/issues/29)).
- `sonar.yml` fails while SonarQube Cloud has an open issue or hotspot that is not accepted:
  a push on those of its branch, a pull request on those it adds
  ([gate-1025](https://github.com/paxel/gates/issues/30)).

### Changed

- The caller templates `ci.yml` and `content-ci.yml` run on pull requests and on pushes to
  `summer`, no longer on every push to every branch
  ([gate-1031](https://github.com/paxel/gates/issues/37)).
- The Python gate and the fuzz workflow run every tool with `uv run --locked`: an outdated
  `uv.lock` fails the run instead of being resolved anew. They also pass `--no-build`: a
  dependency without a wheel fails the gate; only the project itself is still built
  ([gate-1027](https://github.com/paxel/gates/issues/32)).
- The Scorecard template starts with `permissions: contents: read` instead of `read-all`;
  a repository copies the new template
  ([gate-1030](https://github.com/paxel/gates/issues/35)).
- An accepted code-scanning alert that is in a file names that file as `path` in
  `code-scanning-ignores.toml` and is accepted for that file only; an entry that leaves the
  path out blocks ([gate-1022](https://github.com/paxel/gates/issues/27)).

### Security

- The coverage ratchet refuses an lcov path in `coverage-floors.toml` that leaves the
  repository and a part name that is no file name, and no longer looks up on disk the source
  paths a coverage report names ([gate-1026](https://github.com/paxel/gates/issues/31)).

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
