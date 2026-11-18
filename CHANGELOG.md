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

### Changed

- The Java build settings are asked only of a `pom.xml` with Java sources beside it; a sample
  project without code no longer fails the config check and the audit
  ([gate-1038](https://github.com/paxel/gates/issues/51)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
