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

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
