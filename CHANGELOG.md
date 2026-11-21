# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0]

### Added

- `fuzz.yml` takes `stack: dart`: each target is a Dart script run as
  `dart run <target> <seconds>`, with the SDK of the Flutter version in `.fvmrc`
  ([gate-1047](https://github.com/paxel/gates/issues/62)).
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

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
