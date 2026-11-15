# Context

**Standard**: the list of checks, files, settings and badges every active paxel repository
has, in `standard.toml`.

**Active repository**: a repository of paxel that is neither a fork nor archived and has a
commit in the current year.

**Stack**: a kind of code a repository holds, found by its manifest: Rust (`Cargo.toml`),
Dart (`pubspec.yaml`), Go (`go.mod`), TS (`package.json`), Python (`pyproject.toml`), Java
(`pom.xml`). A repository without app code has a **content kind** instead: formulas, scoop
manifests, skills or a static site.

**Applies**: a check applies to a repository when the repository has something for it to look
at. A check that applies is either present or drift; there is no third state.

**Gate**: a step that fails the run on a finding. **Finding**: an open alert, a known
vulnerability, a licence outside the allowlist, a coverage drop, a lint or test failure.

**Accepted finding**: a finding listed in the repository's ignore file with a reason and a
date; it blocks again once the date has passed.

**Shared workflow**: a reusable workflow in gates that a repository calls, pinned by SHA.
**Caller**: the thin workflow in a repository that calls it.

**Drift**: a check that applies to a repository but is missing, different from the standard,
or pinned to a gates version that is behind.

**Floor**: the lowest line coverage a measured part may have; the ratchet raises it to the
measured value minus 0.1 and never lowers it.
