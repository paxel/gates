# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.0]

### Added

- `templates/code-scanning-ignores.toml` carries a commented, dated entry for Scorecard's
  `FuzzingID` in a Dart repository, whose fuzzer Scorecard does not know
  ([gate-1053](https://github.com/paxel/gates/issues/69)).
- A repository declares directories whose manifests are not a stack as `[[NotStacks]]` in a
  `gates.toml` at its root; the audit leaves them out of stack detection and checks that every
  entry has a path and a reason, while the OSV gate still scans them
  ([gate-1052](https://github.com/paxel/gates/issues/68)).

### Fixed

- The verification command in `provenance.yml` names the gates provenance workflow as signer
  and the release tag as source, so it passes for a release attested through gates
  ([gate-1054](https://github.com/paxel/gates/issues/70)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
