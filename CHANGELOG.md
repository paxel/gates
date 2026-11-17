# Changelog

All notable changes to gates are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.2]

### Fixed

- The audit reports a GitHub setting it could not read as "not readable", with GitHub's error,
  instead of "off" ([gate-1035](https://github.com/paxel/gates/issues/47)).
- The OSV gate treats `fuzz/` like every other directory: the fuzz crate is the repository's
  own package and needs no licence acceptance, and an acceptance in `fuzz/osv-scanner.toml`
  needs its reason and date ([gate-1036](https://github.com/paxel/gates/issues/48)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
