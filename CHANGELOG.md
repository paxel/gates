# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.1]

### Fixed

- The OSV gate asks pub.dev up to three times when a licence lookup meets a network error, a
  timeout or a server error, so a short blip no longer blocks every Pub package
  ([gate-1056](https://github.com/paxel/gates/issues/73)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
