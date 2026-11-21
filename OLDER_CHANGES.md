# Older changes

Changes of released versions before the current one, newest first.

## [1.4.0] - 2026-11-21

### Added

- `templates/code-scanning-ignores.toml` carries a commented, dated entry for Scorecard's
  `FuzzingID` in a Dart repository, whose fuzzer Scorecard does not know
  ([gate-1053](https://github.com/paxel/gates/issues/69)).
- `templates/code-scanning-ignores.toml` carries a commented entry for Scorecard's `SASTID`
  next to `MaintainedID`, dated the creation date plus 90 days, for a repository whose first
  commits did not come through pull requests
  ([gate-1055](https://github.com/paxel/gates/issues/71)).
- A repository declares directories whose manifests are not a stack as `[[NotStacks]]` in a
  `gates.toml` at its root; the audit leaves them out of stack detection and checks that every
  entry has a path and a reason, while the OSV gate still scans them
  ([gate-1052](https://github.com/paxel/gates/issues/68)).

### Fixed

- The verification command in `provenance.yml` names the gates provenance workflow as signer
  and the release tag as source, so it passes for a release attested through gates
  ([gate-1054](https://github.com/paxel/gates/issues/70)).

## [1.3.0] - 2026-11-21

### Added

- `fuzz.yml` takes `stack: dart`: each target is a Dart script run as
  `dart run <target> <seconds>`, with the SDK of the Flutter version in `.fvmrc`
  ([gate-1047](https://github.com/paxel/gates/issues/62)).
- `pub.dev` is a distribution badge, and the release template publishes a Dart package to
  pub.dev in a last job, `pub-dev`, after the GitHub release
  ([gate-1048](https://github.com/paxel/gates/issues/63)).
- `templates/osv-scanner.toml` carries dated licence overrides for the PyPI packages `atheris`,
  `colorama` and `avro`, which deps.dev reports without a standard licence
  ([gate-1049](https://github.com/paxel/gates/issues/64)).
- `templates/code-scanning-ignores.toml` carries a commented, dated entry for Scorecard's
  `MaintainedID`, which flags every repository younger than 90 days
  ([gate-1050](https://github.com/paxel/gates/issues/65)).
- The audit's check `secrets` asks for `GATES_ALERTS_TOKEN` in every repository and `SQ_TOKEN`
  in every code repository; `GATES_AUDIT_TOKEN` needs Secrets: read for it
  ([gate-1051](https://github.com/paxel/gates/issues/66)).

### Changed

- `PSF-2.0` is on the licence allowlist, so `typing-extensions` needs no override
  ([gate-1049](https://github.com/paxel/gates/issues/64)).

### Fixed

- The OSV gate no longer blocks every Pub package on an unknown licence: it reads the licence of
  the locked version from pub.dev and blocks only when pub.dev names none or one outside the
  allowlist ([gate-1046](https://github.com/paxel/gates/issues/61)).

## [1.2.0] - 2026-11-19

### Added

- `fuzz.yml` builds Rust targets unoptimised with `rust-dev`, replays the saved crashes of
  `fuzz/regressions/<target>` before fuzzing and runs the caller's `prepare` command once the
  dependencies are installed ([gate-1037](https://github.com/paxel/gates/issues/50)).
- `codeql.yml` takes the caller's CodeQL config with `config-file`
  ([gate-1039](https://github.com/paxel/gates/issues/52)).
- `go.yml` builds and vets every module for the systems named in `cross`
  ([gate-1042](https://github.com/paxel/gates/issues/55)).
- `java.yml` hands the compiled classes to the SonarQube Cloud scan as `coverage/<part>.classes`
  and `coverage/<part>.test-classes` ([gate-1043](https://github.com/paxel/gates/issues/56)).
- `actions/ratchet` checks parts of `coverage-floors.toml` in a job of the repository's own; the
  audit holds its pin to the latest gates release like a shared workflow's
  ([gate-1040](https://github.com/paxel/gates/issues/53)).

### Changed

- The Java build settings are asked only of a `pom.xml` with Java sources beside it; a sample
  project without code no longer fails the config check and the audit
  ([gate-1038](https://github.com/paxel/gates/issues/51)).
- A container image badge and its cosign badge may follow the fixed badge row
  ([gate-1041](https://github.com/paxel/gates/issues/54)).
- The shared ruff config sets no target version; ruff reads `requires-python`, so a package
  that supports an older Python gets no rewrites it cannot run
  ([gate-1044](https://github.com/paxel/gates/issues/57)).
- The sonar job judges a finding by `code-scanning-ignores.toml` alone: SonarQube Cloud's
  quality gate no longer fails it, so an accepted finding on a changed line passes
  ([gate-1045](https://github.com/paxel/gates/issues/59)).

## [1.1.2] - 2026-11-17

### Fixed

- The audit reports a GitHub setting it could not read as "not readable", with GitHub's error,
  instead of "off" ([gate-1035](https://github.com/paxel/gates/issues/47)).
- The OSV gate treats `fuzz/` like every other directory: the fuzz crate is the repository's
  own package and needs no licence acceptance, and an acceptance in `fuzz/osv-scanner.toml`
  needs its reason and date ([gate-1036](https://github.com/paxel/gates/issues/48)).

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
