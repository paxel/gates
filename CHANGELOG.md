# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0]

### Added

- `templates/osv-scanner.toml` carries dated licence overrides for the PyPI packages `atheris`,
  `colorama` and `avro`, which deps.dev reports without a standard licence
  ([gate-1049](https://github.com/paxel/gates/issues/64)).

### Changed

- `PSF-2.0` is on the licence allowlist, so `typing-extensions` needs no override
  ([gate-1049](https://github.com/paxel/gates/issues/64)).

### Fixed

- The OSV gate no longer blocks every Pub package on an unknown licence: it reads the licence of
  the locked version from pub.dev and blocks only when pub.dev names none or one outside the
  allowlist ([gate-1046](https://github.com/paxel/gates/issues/61)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
