# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.0]

### Added

- A repository declares directories whose manifests are not a stack as `[[NotStacks]]` in a
  `gates.toml` at its root; the audit leaves them out of stack detection and checks that every
  entry has a path and a reason, while the OSV gate still scans them
  ([gate-1052](https://github.com/paxel/gates/issues/68)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
