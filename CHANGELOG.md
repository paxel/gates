# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0]

### Fixed

- The OSV gate no longer blocks every Pub package on an unknown licence: it reads the licence of
  the locked version from pub.dev and blocks only when pub.dev names none or one outside the
  allowlist ([gate-1046](https://github.com/paxel/gates/issues/61)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
