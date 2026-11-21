# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.1]

### Fixed

- The OSV gate asks pub.dev up to three times when a licence lookup meets a network error, a
  timeout or a server error, so a short blip no longer blocks every Pub package
  ([gate-1056](https://github.com/paxel/gates/issues/73)).
- The release template publishes to pub.dev only a version that is not there yet, so the tag
  of the first version, published by hand, no longer fails the release
  ([gate-1057](https://github.com/paxel/gates/issues/74)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
