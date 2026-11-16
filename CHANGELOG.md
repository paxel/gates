# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0]

### Added

- The alert gate counts SonarQube Cloud's open issues, of any type and severity, and its
  security hotspots to review; each blocks unless `code-scanning-ignores.toml` accepts it with
  tool "SonarQube Cloud", its rule and its file
  ([gate-1023](https://github.com/paxel/gates/issues/28)).
- `release-gate.yml` reads the SonarQube Cloud findings of every caller that has a
  `sonar-project.properties` and fails when they cannot be read; the weekly Security run
  uses it too ([gate-1024](https://github.com/paxel/gates/issues/29)).
- `sonar.yml` fails on every push and pull request while SonarQube Cloud has an open issue or
  hotspot that is not accepted; a pull request is measured on its own findings and on those of
  its target branch ([gate-1025](https://github.com/paxel/gates/issues/30)).

### Changed

- An accepted code-scanning alert that is in a file names that file as `path` in
  `code-scanning-ignores.toml` and is accepted for that file only; an entry that leaves the
  path out blocks ([gate-1022](https://github.com/paxel/gates/issues/27)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
