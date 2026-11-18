# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0]

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

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
